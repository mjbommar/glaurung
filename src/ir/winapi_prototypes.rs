//! Lightweight WinAPI prototype lookup for decompiler call-site hints.
//!
//! The canonical bundle lives under `data/types/stdlib-winapi-protos.json`
//! for KB import. The native decompiler uses the same data so PE import names
//! such as `ReadFile` can render with argument names and C types without
//! needing an opened KB.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct PrototypeBundle {
    prototypes: Vec<WinApiPrototype>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WinApiPrototype {
    pub name: String,
    pub return_type: String,
    #[serde(default)]
    pub params: Vec<WinApiParam>,
    #[serde(default)]
    pub is_variadic: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WinApiParam {
    pub name: String,
    pub c_type: String,
}

static PROTOTYPES: OnceLock<HashMap<String, WinApiPrototype>> = OnceLock::new();

fn prototypes() -> &'static HashMap<String, WinApiPrototype> {
    PROTOTYPES.get_or_init(|| {
        let raw = include_str!("../../data/types/stdlib-winapi-protos.json");
        let bundle = serde_json::from_str::<PrototypeBundle>(raw)
            .expect("stdlib-winapi-protos.json must parse");
        let mut out = HashMap::new();
        for proto in bundle.prototypes {
            let clean = clean_api_name(&proto.name);
            if clean.is_empty() {
                continue;
            }
            let lower = clean.to_ascii_lowercase();
            out.entry(lower.clone()).or_insert(proto);
            if let Some(stem) = api_stem(&clean) {
                if let Some(proto) = out.get(&lower) {
                    let clone = WinApiPrototype {
                        name: proto.name.clone(),
                        return_type: proto.return_type.clone(),
                        params: proto.params.clone(),
                        is_variadic: proto.is_variadic,
                    };
                    out.entry(stem).or_insert(clone);
                }
            }
        }
        out
    })
}

pub fn lookup(name: &str) -> Option<&'static WinApiPrototype> {
    let clean = clean_api_name(name);
    if clean.is_empty() {
        return None;
    }
    prototypes()
        .get(&clean.to_ascii_lowercase())
        .or_else(|| api_stem(&clean).and_then(|stem| prototypes().get(&stem)))
}

pub fn render_signature(proto: &WinApiPrototype) -> String {
    let mut out = String::new();
    out.push_str(&proto.return_type);
    out.push(' ');
    out.push_str(&proto.name);
    out.push('(');
    if proto.params.is_empty() && !proto.is_variadic {
        out.push_str("void");
    } else {
        for (idx, param) in proto.params.iter().enumerate() {
            if idx > 0 {
                out.push_str(", ");
            }
            out.push_str(&param.c_type);
            out.push(' ');
            out.push_str(&param.name);
        }
        if proto.is_variadic {
            if !proto.params.is_empty() {
                out.push_str(", ");
            }
            out.push_str("...");
        }
    }
    out.push(')');
    out
}

fn clean_api_name(name: &str) -> String {
    let mut clean = name.trim();
    if let Some((_, rhs)) = clean.rsplit_once('!') {
        clean = rhs;
    }
    if let Some((_, rhs)) = clean.rsplit_once("::") {
        clean = rhs;
    }
    for prefix in ["__imp_", "_imp_", "__imp__", "__imp"] {
        if let Some(rest) = clean.strip_prefix(prefix) {
            clean = rest;
            break;
        }
    }
    if clean.starts_with('_') && clean.rsplit_once('@').is_some() {
        clean = clean.trim_start_matches('_');
    }
    if let Some((base, suffix)) = clean.rsplit_once('@') {
        if !base.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit()) {
            clean = base;
        }
    }
    clean.to_string()
}

fn api_stem(name: &str) -> Option<String> {
    let bytes = name.as_bytes();
    if bytes.len() > 2
        && matches!(bytes[bytes.len() - 1], b'A' | b'W')
        && bytes[bytes.len() - 2].is_ascii_lowercase()
    {
        Some(name[..name.len() - 1].to_ascii_lowercase())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{lookup, render_signature};

    #[test]
    fn resolves_import_decorations_and_stdcall_suffixes() {
        let proto = lookup("KERNEL32.dll!__imp__ReadFile@20").expect("ReadFile proto");
        assert_eq!(proto.name, "ReadFile");
        assert!(render_signature(proto).contains("DWORD nNumberOfBytesToRead"));
    }

    #[test]
    fn resolves_a_w_stems_when_exact_suffix_is_missing() {
        let proto = lookup("CreateFile").expect("CreateFile stem");
        assert!(proto.name == "CreateFileA" || proto.name == "CreateFileW");
    }
}
