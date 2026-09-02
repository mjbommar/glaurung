//! Which recovered/DWARF C type spellings the DecBench renderer may emit.
//!
//! Every predicate here is deliberately fail-closed: a spelling the middle IR
//! cannot reconstruct exactly (bitfields, packed layouts, ABI-dependent `long`,
//! arrays, unions, conflicting DWARF definitions, by-value aggregates) is
//! rejected and the render falls back to raw offset arithmetic rather than
//! emitting a type contract it cannot honour.
//!
//! The module is a leaf of the render DAG: it answers questions about type
//! *spellings* and never reaches back into the renderer. Its consumers are the
//! sibling [`decbench_render`](super::decbench_render) front door, the
//! declaration plan, and the `dec` statement printer.

use crate::ir::call_contracts::CallPrototype;

use super::sanitize_c_ident;

fn source_prototype_type_is_renderable(c_type: &str, allow_void: bool) -> bool {
    let normalized = c_type.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty()
        || normalized.contains("/*")
        || normalized
            .chars()
            .any(|ch| matches!(ch, '&' | '[' | ']' | '(' | ')' | ';' | '{' | '}'))
    {
        return false;
    }
    let mut base_spelling = normalized.as_str();
    let mut pointer = false;
    while let Some(inner) = base_spelling.trim_end().strip_suffix('*') {
        pointer = true;
        base_spelling = inner;
    }
    let base = base_spelling
        .split_whitespace()
        .filter(|word| !matches!(*word, "const" | "volatile" | "restrict"))
        .collect::<Vec<_>>()
        .join(" ");
    if base.starts_with("struct ") || base.starts_with("union ") {
        let mut words = base.split_whitespace();
        let tag = words.next();
        let name = words.next();
        return pointer
            && matches!(tag, Some("struct" | "union"))
            && name.is_some_and(valid_c_identifier)
            && words.next().is_none();
    }
    crate::ir::dwarf_type_env::builtin_scalar_type(&base)
        || (base == "void" && (allow_void || pointer))
        || crate::ir::call_contracts::opaque_pointer_typedef(c_type).is_some()
}

pub(crate) fn dwarf_prototype_type_is_renderable(
    c_type: &str,
    allow_void: bool,
    dwarf_type_env: &crate::ir::dwarf_type_env::DwarfTypeEnv<'_>,
) -> bool {
    source_prototype_type_is_renderable(c_type, allow_void)
        || dwarf_type_env.aggregate_pointer(c_type).is_some()
        || dwarf_type_env.aggregate_layout(c_type).is_some()
        || dwarf_type_env.typedef_declaration(c_type).is_some()
}

pub(super) fn source_prototype_forward_declarations(
    prototype: &CallPrototype,
    complete_structs: &std::collections::BTreeSet<String>,
    dwarf_type_env: &crate::ir::dwarf_type_env::DwarfTypeEnv<'_>,
) -> std::collections::BTreeSet<String> {
    let mut declarations = std::collections::BTreeSet::new();
    for c_type in std::iter::once(&prototype.return_type).chain(&prototype.parameter_types) {
        if let Some(pointer) = dwarf_type_env.aggregate_pointer(c_type) {
            if !complete_structs.contains(pointer.source_name) {
                declarations.insert(dwarf_type_env.forward_declaration(pointer));
            }
        } else if let Some(declaration) = dwarf_type_env.typedef_declaration(c_type) {
            declarations.insert(declaration);
        } else if let Some(name) = crate::ir::call_contracts::opaque_pointer_typedef(c_type) {
            declarations.insert(format!("typedef struct __glaurung_opaque_{name} {name};"));
        }
    }
    declarations
}

pub(super) use crate::ir::dwarf_type_env::valid_c_identifier;

fn dwarf_scalar_width(c_type: &str, pointer_width: u8) -> Option<u64> {
    let normalized = c_type.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.ends_with('*') {
        return Some(u64::from(pointer_width));
    }
    match normalized.as_str() {
        "char" | "signed char" | "unsigned char" | "_Bool" | "bool" | "int8_t" | "uint8_t" => {
            Some(1)
        }
        "short" | "short int" | "signed short" | "signed short int" | "unsigned short"
        | "unsigned short int" | "int16_t" | "uint16_t" => Some(2),
        "int" | "signed" | "signed int" | "unsigned" | "unsigned int" | "float" | "int32_t"
        | "uint32_t" => Some(4),
        "long long"
        | "long long int"
        | "signed long long"
        | "signed long long int"
        | "unsigned long long"
        | "unsigned long long int"
        | "long long unsigned"
        | "long long unsigned int"
        | "double"
        | "int64_t"
        | "uint64_t" => Some(8),
        // `long` is ABI-dependent (notably 4 bytes on Win64), and the AST
        // renderer deliberately does not guess the object format here.
        _ => None,
    }
}

pub(super) fn pointed_struct_name(c_type: &str) -> Option<&str> {
    crate::ir::dwarf_type_env::pointed_type_name(c_type)
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    let mask = alignment.checked_sub(1)?;
    value.checked_add(mask).map(|value| value & !mask)
}

/// Select only complete, ordinary-layout structures that the emitted source
/// prototype actually references. This is intentionally fail-closed: bitfields,
/// packed layouts, ABI-dependent `long`, arrays, unions, and conflicting DWARF
/// definitions stay as raw offset accesses until the middle IR can represent
/// them exactly.
pub(super) fn renderable_dwarf_structs<'a>(
    prototype: Option<&CallPrototype>,
    dwarf_types: &'a [crate::debug::dwarf::DwarfType],
    dwarf_type_env: &crate::ir::dwarf_type_env::DwarfTypeEnv<'a>,
    pointer_width: u8,
) -> std::collections::BTreeMap<String, &'a crate::debug::dwarf::DwarfType> {
    let Some(prototype) = prototype else {
        return std::collections::BTreeMap::new();
    };
    let referenced = std::iter::once(&prototype.return_type)
        .chain(&prototype.parameter_types)
        .filter_map(|c_type| {
            dwarf_type_env
                .aggregate_pointer(c_type)
                .filter(|pointer| pointer.kind == crate::debug::dwarf::DwarfTypeKind::Struct)
                .map(|pointer| pointer.tag_name)
                .or_else(|| {
                    dwarf_type_env
                        .aggregate_layout(c_type)
                        .filter(|layout| layout.kind == crate::debug::dwarf::DwarfTypeKind::Struct)
                        .map(|layout| layout.name.as_str())
                })
        })
        .collect::<std::collections::BTreeSet<_>>();
    let mut selected =
        std::collections::BTreeMap::<String, &'a crate::debug::dwarf::DwarfType>::new();
    let mut conflicts = std::collections::BTreeSet::new();
    for layout in dwarf_types.iter().filter(|layout| {
        layout.kind == crate::debug::dwarf::DwarfTypeKind::Struct
            && referenced.contains(layout.name.as_str())
    }) {
        if !valid_c_identifier(&layout.name) || layout.byte_size == 0 || layout.fields.is_empty() {
            continue;
        }
        let mut cursor = 0_u64;
        let mut max_alignment = 1_u64;
        let mut valid = true;
        for field in &layout.fields {
            let Some(width) = dwarf_scalar_width(&field.c_type, pointer_width) else {
                valid = false;
                break;
            };
            let alignment = width.min(u64::from(pointer_width)).max(1);
            max_alignment = max_alignment.max(alignment);
            if !valid_c_identifier(&field.name)
                || !source_prototype_type_is_renderable(&field.c_type, false)
                || align_up(cursor, alignment) != Some(field.offset)
            {
                valid = false;
                break;
            }
            cursor = match field.offset.checked_add(width) {
                Some(end) => end,
                None => {
                    valid = false;
                    break;
                }
            };
        }
        if !valid || align_up(cursor, max_alignment) != Some(layout.byte_size) {
            continue;
        }
        match selected.get(&layout.name) {
            Some(previous) if **previous != *layout => {
                conflicts.insert(layout.name.clone());
            }
            Some(_) => {}
            None => {
                selected.insert(layout.name.clone(), layout);
            }
        }
    }
    for conflict in conflicts {
        selected.remove(&conflict);
    }
    selected
}

pub(super) fn source_type_with_complete_struct_alias(
    c_type: &str,
    complete_structs: &std::collections::BTreeSet<String>,
) -> String {
    let Some(name) = pointed_struct_name(c_type) else {
        return c_type.to_string();
    };
    if !complete_structs.contains(name) {
        return c_type.to_string();
    }
    crate::ir::dwarf_type_env::render_pointer_name(c_type, name)
        .unwrap_or_else(|| c_type.to_string())
}

pub(super) fn collision_safe_local_aggregate_type(
    local_name: &str,
    c_type: &str,
    dwarf_type_env: &crate::ir::dwarf_type_env::DwarfTypeEnv<'_>,
) -> Option<String> {
    let pointer = dwarf_type_env.aggregate_pointer(c_type)?;
    if sanitize_c_ident(local_name) != sanitize_c_ident(pointer.source_name) {
        return None;
    }
    let keyword = match pointer.kind {
        crate::debug::dwarf::DwarfTypeKind::Struct => "struct",
        crate::debug::dwarf::DwarfTypeKind::Union => "union",
        crate::debug::dwarf::DwarfTypeKind::Enum | crate::debug::dwarf::DwarfTypeKind::Typedef => {
            return None
        }
    };
    let qualifiers = c_type
        .find(pointer.source_name)
        .map(|index| c_type[..index].trim())
        .unwrap_or_default()
        .split_whitespace()
        .filter(|token| matches!(*token, "const" | "volatile"))
        .collect::<Vec<_>>()
        .join(" ");
    let qualifiers = if qualifiers.is_empty() {
        String::new()
    } else {
        format!("{qualifiers} ")
    };
    Some(format!("{qualifiers}{keyword} {} *", pointer.tag_name))
}
