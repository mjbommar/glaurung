//! Constant-pool accessors (JVM Specification 4.4).
//!
//! Everything that turns a `constant_pool` index into a Rust value: the
//! UTF-8/class/module/package name readers used across the parser, the
//! member-reference and method-handle decoders, the human-readable display
//! form used by `BootstrapMethods`, and the whole-pool summary.

use super::types::{ClassError, JavaConstantPoolSummary};
use super::CpEntry;

pub(super) fn read_utf8(cp: &[CpEntry], idx: u16) -> Result<String, ClassError> {
    if (idx as usize) >= cp.len() {
        return Err(ClassError::BadCpIndex(idx));
    }
    match &cp[idx as usize] {
        CpEntry::Utf8(s) => Ok(s.clone()),
        _ => Err(ClassError::BadCpIndex(idx)),
    }
}

pub(super) fn read_optional_utf8(cp: &[CpEntry], idx: u16) -> Result<Option<String>, ClassError> {
    if idx == 0 {
        return Ok(None);
    }
    Ok(Some(read_utf8(cp, idx)?))
}

pub(super) fn read_class_name(cp: &[CpEntry], idx: u16) -> Result<String, ClassError> {
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

pub(super) fn read_module_name(cp: &[CpEntry], idx: u16) -> Result<String, ClassError> {
    if (idx as usize) >= cp.len() {
        return Err(ClassError::BadCpIndex(idx));
    }
    match &cp[idx as usize] {
        CpEntry::Module { name_idx } => read_utf8(cp, *name_idx),
        _ => Err(ClassError::BadCpIndex(idx)),
    }
}

pub(super) fn read_package_name(cp: &[CpEntry], idx: u16) -> Result<String, ClassError> {
    if (idx as usize) >= cp.len() {
        return Err(ClassError::BadCpIndex(idx));
    }
    match &cp[idx as usize] {
        CpEntry::Package { name_idx } => read_utf8(cp, *name_idx),
        _ => Err(ClassError::BadCpIndex(idx)),
    }
}

pub(super) fn read_optional_class_name(
    cp: &[CpEntry],
    idx: u16,
) -> Result<Option<String>, ClassError> {
    if idx == 0 {
        return Ok(None);
    }
    Ok(Some(read_class_name(cp, idx)?))
}

pub(super) fn read_u16_from(
    body: &[u8],
    p: &mut usize,
    context: &'static str,
) -> Result<u16, ClassError> {
    if *p + 2 > body.len() {
        return Err(ClassError::Truncated(context));
    }
    let value = u16::from_be_bytes(body[*p..*p + 2].try_into().unwrap());
    *p += 2;
    Ok(value)
}

pub(super) fn summarize_constant_pool(cp: &[CpEntry]) -> JavaConstantPoolSummary {
    let mut summary = JavaConstantPoolSummary {
        total_slots: cp.len().saturating_sub(1) as u16,
        ..JavaConstantPoolSummary::default()
    };
    for entry in cp.iter().skip(1) {
        match entry {
            CpEntry::Empty => summary.empty_slots += 1,
            CpEntry::Utf8(_) => summary.utf8_count += 1,
            CpEntry::Integer(_) => summary.integer_count += 1,
            CpEntry::Float(_) => summary.float_count += 1,
            CpEntry::Long(_) => summary.long_count += 1,
            CpEntry::Double(_) => summary.double_count += 1,
            CpEntry::Class { .. } => summary.class_count += 1,
            CpEntry::String { .. } => summary.string_count += 1,
            CpEntry::Fieldref { .. } => summary.fieldref_count += 1,
            CpEntry::Methodref { .. } => summary.methodref_count += 1,
            CpEntry::InterfaceMethodref { .. } => summary.interface_methodref_count += 1,
            CpEntry::NameAndType { .. } => summary.name_and_type_count += 1,
            CpEntry::MethodHandle { .. } => summary.method_handle_count += 1,
            CpEntry::MethodType { .. } => summary.method_type_count += 1,
            CpEntry::Dynamic { .. } => summary.dynamic_count += 1,
            CpEntry::InvokeDynamic { .. } => summary.invoke_dynamic_count += 1,
            CpEntry::Module { .. } => summary.module_count += 1,
            CpEntry::Package { .. } => summary.package_count += 1,
        }
    }
    summary.populated_entries = summary.total_slots.saturating_sub(summary.empty_slots);
    summary
}

pub(super) fn read_method_handle_details(
    cp: &[CpEntry],
    idx: u16,
) -> Result<
    (
        Option<u8>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ),
    ClassError,
> {
    if (idx as usize) >= cp.len() {
        return Err(ClassError::BadCpIndex(idx));
    }
    let CpEntry::MethodHandle {
        reference_kind,
        reference_index,
    } = &cp[idx as usize]
    else {
        return Ok((None, None, None, None, None, Some(format!("cp#{idx}"))));
    };
    let (owner, name, descriptor, target) = read_member_reference(cp, *reference_index)?;
    Ok((
        Some(*reference_kind),
        Some(method_handle_kind_name(*reference_kind).to_string()),
        Some(owner),
        Some(name),
        Some(descriptor),
        Some(target),
    ))
}

fn read_member_reference(
    cp: &[CpEntry],
    idx: u16,
) -> Result<(String, String, String, String), ClassError> {
    if (idx as usize) >= cp.len() {
        return Err(ClassError::BadCpIndex(idx));
    }
    let (class_idx, name_and_type_idx) = match &cp[idx as usize] {
        CpEntry::Fieldref {
            class_idx,
            name_and_type_idx,
        }
        | CpEntry::Methodref {
            class_idx,
            name_and_type_idx,
        }
        | CpEntry::InterfaceMethodref {
            class_idx,
            name_and_type_idx,
        } => (*class_idx, *name_and_type_idx),
        _ => return Err(ClassError::BadCpIndex(idx)),
    };
    let owner = read_class_name(cp, class_idx)?;
    let (name, descriptor) = read_name_and_type(cp, name_and_type_idx)?;
    let target = format!("{owner}.{name}:{descriptor}");
    Ok((owner, name, descriptor, target))
}

pub(super) fn read_constant_pool_display(cp: &[CpEntry], idx: u16) -> Result<String, ClassError> {
    if (idx as usize) >= cp.len() {
        return Err(ClassError::BadCpIndex(idx));
    }
    match &cp[idx as usize] {
        CpEntry::Utf8(value) => Ok(value.clone()),
        CpEntry::Integer(value) => Ok(value.to_string()),
        CpEntry::Float(bits) => Ok(f32::from_bits(*bits).to_string()),
        CpEntry::Long(value) => Ok(value.to_string()),
        CpEntry::Double(bits) => Ok(f64::from_bits(*bits).to_string()),
        CpEntry::String { string_idx } => read_utf8(cp, *string_idx),
        CpEntry::Class { name_idx } => read_utf8(cp, *name_idx),
        CpEntry::MethodType { descriptor_idx } => read_utf8(cp, *descriptor_idx),
        CpEntry::MethodHandle { .. } => {
            let (_, _, _, _, _, target) = read_method_handle_details(cp, idx)?;
            Ok(target.unwrap_or_else(|| format!("cp#{idx}")))
        }
        CpEntry::NameAndType { name_idx, desc_idx } => Ok(format!(
            "{}:{}",
            read_utf8(cp, *name_idx)?,
            read_utf8(cp, *desc_idx)?
        )),
        CpEntry::Fieldref { .. }
        | CpEntry::Methodref { .. }
        | CpEntry::InterfaceMethodref { .. } => {
            let (_, _, _, target) = read_member_reference(cp, idx)?;
            Ok(target)
        }
        CpEntry::Dynamic {
            bootstrap_method_attr_idx,
            name_and_type_idx,
        } => {
            let (name, descriptor) = read_name_and_type(cp, *name_and_type_idx)?;
            Ok(format!(
                "dynamic#{bootstrap_method_attr_idx}:{name}:{descriptor}"
            ))
        }
        CpEntry::InvokeDynamic {
            bootstrap_method_attr_idx,
            name_and_type_idx,
        } => {
            let (name, descriptor) = read_name_and_type(cp, *name_and_type_idx)?;
            Ok(format!(
                "invokedynamic#{bootstrap_method_attr_idx}:{name}:{descriptor}"
            ))
        }
        CpEntry::Module { name_idx } | CpEntry::Package { name_idx } => read_utf8(cp, *name_idx),
        CpEntry::Empty => Ok(format!("cp#{idx}")),
    }
}

fn method_handle_kind_name(kind: u8) -> &'static str {
    match kind {
        1 => "get_field",
        2 => "get_static",
        3 => "put_field",
        4 => "put_static",
        5 => "invoke_virtual",
        6 => "invoke_static",
        7 => "invoke_special",
        8 => "new_invoke_special",
        9 => "invoke_interface",
        _ => "unknown",
    }
}

pub(super) fn read_name_and_type(cp: &[CpEntry], idx: u16) -> Result<(String, String), ClassError> {
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
