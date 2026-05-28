//! Windows metadata extraction helpers.
//!
//! Microsoft publishes Win32 and WDK API metadata as ECMA-335 `.winmd`
//! files. This module normalizes P/Invoke method definitions into the
//! prototype bundle format used by the Python knowledge-base importer.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use windows_metadata::{reader::TypeIndex, MethodCallAttributes, Type};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WinmdPrototypeParam {
    pub name: String,
    pub c_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WinmdPrototype {
    pub name: String,
    pub return_type: String,
    pub params: Vec<WinmdPrototypeParam>,
    pub is_variadic: bool,
    pub namespace: String,
    pub metadata_type: String,
    pub import_name: String,
    pub module: Option<String>,
    pub calling_convention: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WinmdExport {
    pub prototypes: Vec<WinmdPrototype>,
    pub type_count: usize,
    pub method_count: usize,
    pub pinvoke_count: usize,
}

pub fn export_winmd_prototypes(path: &Path) -> Result<WinmdExport> {
    let index = TypeIndex::read(path)
        .ok_or_else(|| anyhow!("failed to read Windows metadata file: {}", path.display()))?;

    let mut prototypes: BTreeMap<(String, String, String), WinmdPrototype> = BTreeMap::new();
    let mut type_count = 0usize;
    let mut method_count = 0usize;
    let mut pinvoke_count = 0usize;

    for (_namespace_key, _name_key, ty) in index.iter() {
        type_count += 1;
        let namespace = ty.namespace().to_string();
        let metadata_type = ty.name().to_string();
        let generics: Vec<Type> = Vec::new();

        for method in ty.methods() {
            method_count += 1;
            let Some(impl_map) = method.impl_map() else {
                continue;
            };
            pinvoke_count += 1;

            let signature = method.signature(&generics);
            let params_by_sequence: BTreeMap<u16, String> = method
                .params()
                .filter(|param| param.sequence() > 0)
                .map(|param| (param.sequence(), param.name().to_string()))
                .collect();
            let params = signature
                .types
                .iter()
                .enumerate()
                .map(|(idx, ty)| WinmdPrototypeParam {
                    name: params_by_sequence
                        .get(&u16::try_from(idx + 1).unwrap_or(u16::MAX))
                        .cloned()
                        .unwrap_or_else(|| format!("arg{idx}")),
                    c_type: render_c_type(ty),
                })
                .collect();

            let import_name = impl_map.import_name().to_string();
            let name = if import_name.is_empty() {
                method.name().to_string()
            } else {
                import_name.clone()
            };
            if name.is_empty() {
                continue;
            }

            let calling_convention = method.calling_convention();
            let proto = WinmdPrototype {
                name: name.clone(),
                return_type: render_c_type(&signature.return_type),
                params,
                is_variadic: signature.flags.contains(MethodCallAttributes::VARARG),
                namespace: namespace.clone(),
                metadata_type: metadata_type.clone(),
                import_name,
                module: Some(impl_map.import_scope().name().to_string())
                    .filter(|module| !module.is_empty()),
                calling_convention: Some(calling_convention.to_string())
                    .filter(|cc| !cc.is_empty()),
            };
            prototypes
                .entry((name, namespace.clone(), metadata_type.clone()))
                .or_insert(proto);
        }
    }

    Ok(WinmdExport {
        prototypes: prototypes.into_values().collect(),
        type_count,
        method_count,
        pinvoke_count,
    })
}

fn render_c_type(ty: &Type) -> String {
    match ty {
        Type::Void => "void".to_string(),
        Type::Bool => "bool".to_string(),
        Type::Char => "char16_t".to_string(),
        Type::I8 => "int8_t".to_string(),
        Type::U8 => "uint8_t".to_string(),
        Type::I16 => "int16_t".to_string(),
        Type::U16 => "uint16_t".to_string(),
        Type::I32 => "int32_t".to_string(),
        Type::U32 => "uint32_t".to_string(),
        Type::I64 => "int64_t".to_string(),
        Type::U64 => "uint64_t".to_string(),
        Type::F32 => "float".to_string(),
        Type::F64 => "double".to_string(),
        Type::ISize => "intptr_t".to_string(),
        Type::USize => "uintptr_t".to_string(),
        Type::String => "HSTRING".to_string(),
        Type::Object => "void *".to_string(),
        Type::AttributeEnum => "int32_t".to_string(),
        Type::Name(name) => render_name_type(&name.name),
        Type::Array(inner) => format!("{} *", render_c_type(inner)),
        Type::ArrayRef(inner) => format!("{} *", render_c_type(inner)),
        Type::Generic(idx) => format!("T{idx}"),
        Type::RefMut(inner) => format!("{} *", render_c_type(inner)),
        Type::RefConst(inner) => format!("const {} *", render_c_type(inner)),
        Type::PtrMut(inner, depth) => render_pointer_type(inner, *depth, false),
        Type::PtrConst(inner, depth) => render_pointer_type(inner, *depth, true),
        Type::ArrayFixed(inner, len) => format!("{}[{len}]", render_c_type(inner)),
    }
}

fn render_name_type(name: &str) -> String {
    let clean = name.strip_suffix('`').unwrap_or(name);
    match clean {
        "Boolean" => "bool".to_string(),
        "Byte" => "uint8_t".to_string(),
        "Char" => "char16_t".to_string(),
        "Double" => "double".to_string(),
        "Guid" => "GUID".to_string(),
        "Int16" => "int16_t".to_string(),
        "Int32" => "int32_t".to_string(),
        "Int64" => "int64_t".to_string(),
        "IntPtr" => "intptr_t".to_string(),
        "Object" => "void *".to_string(),
        "SByte" => "int8_t".to_string(),
        "Single" => "float".to_string(),
        "String" => "HSTRING".to_string(),
        "UInt16" => "uint16_t".to_string(),
        "UInt32" => "uint32_t".to_string(),
        "UInt64" => "uint64_t".to_string(),
        "UIntPtr" => "uintptr_t".to_string(),
        "Void" => "void".to_string(),
        rest => rest.to_string(),
    }
}

fn render_pointer_type(inner: &Type, depth: usize, is_const: bool) -> String {
    let mut out = render_c_type(inner);
    if is_const {
        out = format!("const {out}");
    }
    for _ in 0..depth.max(1) {
        out.push_str(" *");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{render_c_type, Type};

    #[test]
    fn renders_basic_and_pointer_types() {
        assert_eq!(render_c_type(&Type::U32), "uint32_t");
        assert_eq!(
            render_c_type(&Type::PtrConst(Box::new(Type::U8), 1)),
            "const uint8_t *"
        );
        assert_eq!(
            render_c_type(&Type::PtrMut(Box::new(Type::named("x", "HANDLE")), 1)),
            "HANDLE *"
        );
    }
}
