//! Annotations and element values (JVM Specification 4.7.16-4.7.22).
//!
//! The `RuntimeVisible`/`RuntimeInvisible` annotation tables, the recursive
//! `element_value` decoder behind them, `MethodParameters`,
//! `RuntimeVisibleParameterAnnotations`, and the `ConstantValue` reader that
//! shares their constant-pool shapes.

use super::constant_pool::{read_optional_utf8, read_utf8};
use super::types::{
    ClassError, JavaAnnotation, JavaAnnotationElement, JavaAnnotationValue, JavaConstantValue,
    JavaMethodParameter, JavaParameterAnnotations,
};
use super::CpEntry;

pub(super) fn parse_annotations_attribute(
    body: &[u8],
    cp: &[CpEntry],
    visibility: &str,
) -> Result<Vec<JavaAnnotation>, ClassError> {
    if body.len() < 2 {
        return Err(ClassError::Truncated("annotations length"));
    }
    let count = u16::from_be_bytes(body[0..2].try_into().unwrap()) as usize;
    let mut out = Vec::with_capacity(count);
    let mut p = 2usize;
    for _ in 0..count {
        let (next, annotation) = parse_annotation(body, p, cp, visibility)?;
        p = next;
        out.push(annotation);
    }
    Ok(out)
}

pub(super) fn parse_method_parameters_attribute(
    body: &[u8],
    cp: &[CpEntry],
) -> Result<Vec<JavaMethodParameter>, ClassError> {
    if body.is_empty() {
        return Err(ClassError::Truncated("MethodParameters length"));
    }
    let count = body[0] as usize;
    let mut p = 1usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if p + 4 > body.len() {
            return Err(ClassError::Truncated("MethodParameters body"));
        }
        let name_idx = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
        let access_flags = u16::from_be_bytes(body[p + 2..p + 4].try_into().unwrap());
        p += 4;
        out.push(JavaMethodParameter {
            name: read_optional_utf8(cp, name_idx)?,
            access_flags,
        });
    }
    Ok(out)
}

pub(super) fn parse_parameter_annotations_attribute(
    body: &[u8],
    cp: &[CpEntry],
    visibility: &str,
) -> Result<Vec<JavaParameterAnnotations>, ClassError> {
    if body.is_empty() {
        return Err(ClassError::Truncated("parameter annotations length"));
    }
    let count = body[0] as usize;
    let mut p = 1usize;
    let mut out = Vec::with_capacity(count);
    for parameter_index in 0..count {
        if p + 2 > body.len() {
            return Err(ClassError::Truncated("parameter annotations body"));
        }
        let annotation_count = u16::from_be_bytes(body[p..p + 2].try_into().unwrap()) as usize;
        p += 2;
        let mut annotations = Vec::with_capacity(annotation_count);
        for _ in 0..annotation_count {
            let (next, annotation) = parse_annotation(body, p, cp, visibility)?;
            p = next;
            annotations.push(annotation);
        }
        out.push(JavaParameterAnnotations {
            parameter_index: parameter_index as u16,
            annotations,
        });
    }
    Ok(out)
}

fn parse_annotation(
    body: &[u8],
    mut p: usize,
    cp: &[CpEntry],
    visibility: &str,
) -> Result<(usize, JavaAnnotation), ClassError> {
    if p + 4 > body.len() {
        return Err(ClassError::Truncated("annotation header"));
    }
    let type_idx = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
    p += 2;
    let pair_count = u16::from_be_bytes(body[p..p + 2].try_into().unwrap()) as usize;
    p += 2;
    let mut elements = Vec::with_capacity(pair_count);
    for _ in 0..pair_count {
        if p + 2 > body.len() {
            return Err(ClassError::Truncated("annotation element name"));
        }
        let name_idx = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
        p += 2;
        let (next, value) = parse_annotation_element_value(body, p, cp)?;
        p = next;
        elements.push(JavaAnnotationElement {
            name: read_utf8(cp, name_idx)?,
            value,
        });
    }
    Ok((
        p,
        JavaAnnotation {
            visibility: visibility.to_string(),
            descriptor: read_utf8(cp, type_idx)?,
            elements,
        },
    ))
}

pub(super) fn parse_annotation_element_value(
    body: &[u8],
    mut p: usize,
    cp: &[CpEntry],
) -> Result<(usize, JavaAnnotationValue), ClassError> {
    if p >= body.len() {
        return Err(ClassError::Truncated("annotation element tag"));
    }
    let tag_byte = body[p];
    p += 1;
    let tag = (tag_byte as char).to_string();
    match tag_byte as char {
        'B' | 'C' | 'D' | 'F' | 'I' | 'J' | 'S' | 'Z' | 's' => {
            if p + 2 > body.len() {
                return Err(ClassError::Truncated("annotation const value"));
            }
            let const_idx = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
            p += 2;
            Ok((
                p,
                JavaAnnotationValue {
                    tag,
                    kind: "const".to_string(),
                    value: Some(read_annotation_const_value(cp, const_idx)?),
                    type_name: None,
                    const_name: None,
                    values: Vec::new(),
                },
            ))
        }
        'e' => {
            if p + 4 > body.len() {
                return Err(ClassError::Truncated("annotation enum value"));
            }
            let type_name_idx = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
            let const_name_idx = u16::from_be_bytes(body[p + 2..p + 4].try_into().unwrap());
            p += 4;
            Ok((
                p,
                JavaAnnotationValue {
                    tag,
                    kind: "enum".to_string(),
                    value: None,
                    type_name: Some(read_utf8(cp, type_name_idx)?),
                    const_name: Some(read_utf8(cp, const_name_idx)?),
                    values: Vec::new(),
                },
            ))
        }
        'c' => {
            if p + 2 > body.len() {
                return Err(ClassError::Truncated("annotation class value"));
            }
            let class_info_idx = u16::from_be_bytes(body[p..p + 2].try_into().unwrap());
            p += 2;
            Ok((
                p,
                JavaAnnotationValue {
                    tag,
                    kind: "class".to_string(),
                    value: Some(read_utf8(cp, class_info_idx)?),
                    type_name: None,
                    const_name: None,
                    values: Vec::new(),
                },
            ))
        }
        '@' => {
            let (next, annotation) = parse_annotation(body, p, cp, "nested")?;
            Ok((
                next,
                JavaAnnotationValue {
                    tag,
                    kind: "annotation".to_string(),
                    value: Some(annotation.descriptor),
                    type_name: None,
                    const_name: None,
                    values: Vec::new(),
                },
            ))
        }
        '[' => {
            if p + 2 > body.len() {
                return Err(ClassError::Truncated("annotation array length"));
            }
            let count = u16::from_be_bytes(body[p..p + 2].try_into().unwrap()) as usize;
            p += 2;
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                let (next, value) = parse_annotation_element_value(body, p, cp)?;
                p = next;
                values.push(value);
            }
            Ok((
                p,
                JavaAnnotationValue {
                    tag,
                    kind: "array".to_string(),
                    value: None,
                    type_name: None,
                    const_name: None,
                    values,
                },
            ))
        }
        _ => Err(ClassError::BadCpTag(tag_byte)),
    }
}

fn read_annotation_const_value(cp: &[CpEntry], idx: u16) -> Result<String, ClassError> {
    if (idx as usize) >= cp.len() {
        return Err(ClassError::BadCpIndex(idx));
    }
    match &cp[idx as usize] {
        CpEntry::Utf8(s) => Ok(s.clone()),
        CpEntry::String { string_idx } => read_utf8(cp, *string_idx),
        CpEntry::Class { name_idx } => read_utf8(cp, *name_idx),
        _ => Ok(format!("cp#{idx}")),
    }
}

pub(super) fn read_constant_value(
    cp: &[CpEntry],
    idx: u16,
) -> Result<JavaConstantValue, ClassError> {
    if (idx as usize) >= cp.len() {
        return Err(ClassError::BadCpIndex(idx));
    }
    match &cp[idx as usize] {
        CpEntry::Integer(value) => Ok(JavaConstantValue {
            kind: "int".to_string(),
            value: value.to_string(),
        }),
        CpEntry::Float(bits) => Ok(JavaConstantValue {
            kind: "float".to_string(),
            value: f32::from_bits(*bits).to_string(),
        }),
        CpEntry::Long(value) => Ok(JavaConstantValue {
            kind: "long".to_string(),
            value: value.to_string(),
        }),
        CpEntry::Double(bits) => Ok(JavaConstantValue {
            kind: "double".to_string(),
            value: f64::from_bits(*bits).to_string(),
        }),
        CpEntry::String { string_idx } => Ok(JavaConstantValue {
            kind: "string".to_string(),
            value: read_utf8(cp, *string_idx)?,
        }),
        _ => Ok(JavaConstantValue {
            kind: "cp".to_string(),
            value: format!("cp#{idx}"),
        }),
    }
}
