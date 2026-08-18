//! The `Code` attribute and its sub-tables (JVM Specification 4.7.3).
//!
//! [`parse_code_attribute`] decodes one method body's frame sizes, exception
//! table, `StackMapTable` frame count and debug tables
//! (`LineNumberTable`, `LocalVariableTable`, `LocalVariableTypeTable`), and
//! calls into `bytecode` for the instruction stream itself. The small
//! count-only attribute readers shared with the member walk live here too.

use super::bytecode::{parse_code_instructions, parse_code_xrefs};
use super::constant_pool::{read_class_name, read_utf8};
use super::types::{
    ClassError, JavaCode, JavaExceptionHandler, JavaLineNumber, JavaLocalVariable,
    JavaLocalVariableType,
};
use super::CpEntry;

pub(super) fn parse_code_attribute(body: &[u8], cp: &[CpEntry]) -> Result<JavaCode, ClassError> {
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
    let exception_handlers = parse_exception_table(
        &body[code_end + 2..exception_table_end],
        exception_table_len,
        cp,
    )?;
    let attributes_count = u16::from_be_bytes(
        body[exception_table_end..exception_table_end + 2]
            .try_into()
            .unwrap(),
    );
    let mut p = exception_table_end + 2;
    let mut line_numbers = Vec::new();
    let mut local_variables = Vec::new();
    let mut local_variable_types = Vec::new();
    let mut attribute_names = Vec::with_capacity(attributes_count as usize);
    let mut stack_map_frame_count = 0u16;
    let mut runtime_visible_type_annotation_count = 0u16;
    let mut runtime_invisible_type_annotation_count = 0u16;
    for _ in 0..attributes_count {
        if p + 6 > body.len() {
            return Err(ClassError::Truncated("code nested attribute header"));
        }
        let name_idx = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
        let name = read_utf8(cp, name_idx)?;
        let alen = u32::from_be_bytes(body[p + 2..p + 6].try_into().unwrap()) as usize;
        let attr_start = p + 6;
        let attr_end = attr_start
            .checked_add(alen)
            .ok_or(ClassError::Truncated("code nested attribute body"))?;
        if attr_end > body.len() {
            return Err(ClassError::Truncated("code nested attribute body"));
        }
        attribute_names.push(name.clone());
        if name == "LineNumberTable" {
            line_numbers.extend(parse_line_number_table(&body[attr_start..attr_end])?);
        } else if name == "LocalVariableTable" {
            local_variables.extend(parse_local_variable_table(&body[attr_start..attr_end], cp)?);
        } else if name == "LocalVariableTypeTable" {
            local_variable_types.extend(parse_local_variable_type_table(
                &body[attr_start..attr_end],
                cp,
            )?);
        } else if name == "StackMapTable" {
            stack_map_frame_count = parse_stack_map_table_frame_count(&body[attr_start..attr_end])?;
        } else if name == "RuntimeVisibleTypeAnnotations" {
            runtime_visible_type_annotation_count = parse_counted_attribute(
                &body[attr_start..attr_end],
                "RuntimeVisibleTypeAnnotations",
            )?;
        } else if name == "RuntimeInvisibleTypeAnnotations" {
            runtime_invisible_type_annotation_count = parse_counted_attribute(
                &body[attr_start..attr_end],
                "RuntimeInvisibleTypeAnnotations",
            )?;
        }
        p = attr_end;
    }
    let code_bytes = &body[code_start..code_end];
    let instructions = parse_code_instructions(code_bytes)?;
    let instruction_count = instructions.len() as u32;
    let unknown_instruction_count = instructions
        .iter()
        .filter(|instruction| instruction.mnemonic.starts_with("unknown_0x"))
        .count() as u32;
    let xrefs = parse_code_xrefs(code_bytes, cp)?;
    Ok(JavaCode {
        max_stack,
        max_locals,
        code_length,
        exception_table_len,
        exception_handlers,
        attributes_count,
        attribute_names,
        instruction_count,
        unknown_instruction_count,
        stack_map_frame_count,
        runtime_visible_type_annotation_count,
        runtime_invisible_type_annotation_count,
        line_numbers,
        local_variables,
        local_variable_types,
        instructions,
        xrefs,
    })
}

fn parse_exception_table(
    body: &[u8],
    exception_table_len: u16,
    cp: &[CpEntry],
) -> Result<Vec<JavaExceptionHandler>, ClassError> {
    let expected_len = (exception_table_len as usize)
        .checked_mul(8)
        .ok_or(ClassError::Truncated("exception table"))?;
    if body.len() < expected_len {
        return Err(ClassError::Truncated("exception table"));
    }
    let mut handlers = Vec::with_capacity(exception_table_len as usize);
    let mut p = 0usize;
    for _ in 0..exception_table_len {
        let start_pc = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
        let end_pc = u16::from_be_bytes(body[p + 2..p + 4].try_into().unwrap());
        let handler_pc = u16::from_be_bytes(body[p + 4..p + 6].try_into().unwrap());
        let catch_type_idx = u16::from_be_bytes(body[p + 6..p + 8].try_into().unwrap());
        let catch_type = if catch_type_idx == 0 {
            None
        } else {
            Some(read_class_name(cp, catch_type_idx)?)
        };
        handlers.push(JavaExceptionHandler {
            start_pc,
            end_pc,
            handler_pc,
            catch_type,
        });
        p += 8;
    }
    Ok(handlers)
}

fn parse_stack_map_table_frame_count(body: &[u8]) -> Result<u16, ClassError> {
    if body.len() < 2 {
        return Err(ClassError::Truncated("StackMapTable length"));
    }
    Ok(u16::from_be_bytes(body[0..2].try_into().unwrap()))
}

pub(super) fn parse_counted_attribute(
    body: &[u8],
    attribute_name: &'static str,
) -> Result<u16, ClassError> {
    if body.len() < 2 {
        return Err(ClassError::Truncated(attribute_name));
    }
    Ok(u16::from_be_bytes(body[0..2].try_into().unwrap()))
}

pub(super) fn parse_exceptions_attribute(
    body: &[u8],
    cp: &[CpEntry],
) -> Result<Vec<String>, ClassError> {
    if body.len() < 2 {
        return Err(ClassError::Truncated("Exceptions length"));
    }
    let count = u16::from_be_bytes(body[0..2].try_into().unwrap()) as usize;
    let expected_len = 2usize
        .checked_add(
            count
                .checked_mul(2)
                .ok_or(ClassError::Truncated("Exceptions body"))?,
        )
        .ok_or(ClassError::Truncated("Exceptions body"))?;
    if expected_len > body.len() {
        return Err(ClassError::Truncated("Exceptions body"));
    }
    let mut out = Vec::with_capacity(count);
    let mut p = 2usize;
    for _ in 0..count {
        let class_idx = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
        out.push(read_class_name(cp, class_idx)?);
        p += 2;
    }
    Ok(out)
}

fn parse_line_number_table(body: &[u8]) -> Result<Vec<JavaLineNumber>, ClassError> {
    if body.len() < 2 {
        return Err(ClassError::Truncated("LineNumberTable length"));
    }
    let count = u16::from_be_bytes(body[0..2].try_into().unwrap()) as usize;
    let expected_len = 2usize
        .checked_add(
            count
                .checked_mul(4)
                .ok_or(ClassError::Truncated("LineNumberTable body"))?,
        )
        .ok_or(ClassError::Truncated("LineNumberTable body"))?;
    if expected_len > body.len() {
        return Err(ClassError::Truncated("LineNumberTable body"));
    }
    let mut out = Vec::with_capacity(count);
    let mut p = 2usize;
    for _ in 0..count {
        let start_pc = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
        let line_number = u16::from_be_bytes(body[p + 2..p + 4].try_into().unwrap());
        out.push(JavaLineNumber {
            start_pc,
            line_number,
        });
        p += 4;
    }
    Ok(out)
}

fn parse_local_variable_table(
    body: &[u8],
    cp: &[CpEntry],
) -> Result<Vec<JavaLocalVariable>, ClassError> {
    if body.len() < 2 {
        return Err(ClassError::Truncated("LocalVariableTable length"));
    }
    let count = u16::from_be_bytes(body[0..2].try_into().unwrap()) as usize;
    let expected_len = 2usize
        .checked_add(
            count
                .checked_mul(10)
                .ok_or(ClassError::Truncated("LocalVariableTable body"))?,
        )
        .ok_or(ClassError::Truncated("LocalVariableTable body"))?;
    if expected_len > body.len() {
        return Err(ClassError::Truncated("LocalVariableTable body"));
    }
    let mut out = Vec::with_capacity(count);
    let mut p = 2usize;
    for _ in 0..count {
        let start_pc = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
        let length = u16::from_be_bytes(body[p + 2..p + 4].try_into().unwrap());
        let name_idx = u16::from_be_bytes(body[p + 4..p + 6].try_into().unwrap());
        let descriptor_idx = u16::from_be_bytes(body[p + 6..p + 8].try_into().unwrap());
        let index = u16::from_be_bytes(body[p + 8..p + 10].try_into().unwrap());
        out.push(JavaLocalVariable {
            start_pc,
            length,
            name: read_utf8(cp, name_idx)?,
            descriptor: read_utf8(cp, descriptor_idx)?,
            index,
        });
        p += 10;
    }
    Ok(out)
}

fn parse_local_variable_type_table(
    body: &[u8],
    cp: &[CpEntry],
) -> Result<Vec<JavaLocalVariableType>, ClassError> {
    if body.len() < 2 {
        return Err(ClassError::Truncated("LocalVariableTypeTable length"));
    }
    let count = u16::from_be_bytes(body[0..2].try_into().unwrap()) as usize;
    let expected_len = 2usize
        .checked_add(
            count
                .checked_mul(10)
                .ok_or(ClassError::Truncated("LocalVariableTypeTable body"))?,
        )
        .ok_or(ClassError::Truncated("LocalVariableTypeTable body"))?;
    if expected_len > body.len() {
        return Err(ClassError::Truncated("LocalVariableTypeTable body"));
    }
    let mut out = Vec::with_capacity(count);
    let mut p = 2usize;
    for _ in 0..count {
        let start_pc = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
        let length = u16::from_be_bytes(body[p + 2..p + 4].try_into().unwrap());
        let name_idx = u16::from_be_bytes(body[p + 4..p + 6].try_into().unwrap());
        let signature_idx = u16::from_be_bytes(body[p + 6..p + 8].try_into().unwrap());
        let index = u16::from_be_bytes(body[p + 8..p + 10].try_into().unwrap());
        out.push(JavaLocalVariableType {
            start_pc,
            length,
            name: read_utf8(cp, name_idx)?,
            signature: read_utf8(cp, signature_idx)?,
            index,
        });
        p += 10;
    }
    Ok(out)
}
