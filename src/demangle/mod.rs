//! Demangler helpers for Rust and C++ (Itanium) symbols.
//!
//! MSVC demangling is left as a future enhancement; we detect MSVC-style
//! patterns but only return the original name for now.

use crate::strings::patterns;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolFlavor {
    Rust,
    Itanium,
    Msvc,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemangleResult {
    pub original: String,
    pub demangled: String,
    pub flavor: SymbolFlavor,
}

pub fn detect_flavor(s: &str) -> SymbolFlavor {
    if rustc_demangle::try_demangle(s).is_ok() {
        return SymbolFlavor::Rust;
    }
    if patterns::RE_ITA_MANGLED.is_match(s) {
        return SymbolFlavor::Itanium;
    }
    if patterns::RE_MSVC_MANGLED.is_match(s) {
        return SymbolFlavor::Msvc;
    }
    SymbolFlavor::Unknown
}

/// Attempt to demangle a single symbol. Returns None when not recognized.
pub fn demangle_one(s: &str) -> Option<DemangleResult> {
    // Rust (v0 + legacy) demangler
    if let Ok(dm) = rustc_demangle::try_demangle(s) {
        let out = dm.to_string();
        return Some(DemangleResult {
            original: s.to_string(),
            demangled: out,
            flavor: SymbolFlavor::Rust,
        });
    }
    // C++ (Itanium) demangler
    if patterns::RE_ITA_MANGLED.is_match(s) {
        if let Ok(sym) = cpp_demangle::Symbol::new(s) {
            let out = sym.to_string();
            return Some(DemangleResult {
                original: s.to_string(),
                demangled: out,
                flavor: SymbolFlavor::Itanium,
            });
        }
    }
    // MSVC demangler
    if patterns::RE_MSVC_MANGLED.is_match(s) {
        if let Ok(out) = msvc_demangler::demangle(s, msvc_demangler::DemangleFlags::COMPLETE) {
            return Some(DemangleResult {
                original: s.to_string(),
                demangled: out,
                flavor: SymbolFlavor::Msvc,
            });
        }
    }
    None
}

/// Demangle a stream of candidate names with a cap on results.
pub fn demangle_many<'a, I: IntoIterator<Item = &'a str>>(
    iter: I,
    max: usize,
) -> Vec<DemangleResult> {
    let mut out = Vec::new();
    for s in iter {
        if out.len() >= max {
            break;
        }
        if let Some(r) = demangle_one(s) {
            out.push(r);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_flavor_simple() {
        assert_ne!(detect_flavor("_Z3foov"), SymbolFlavor::Unknown);
        assert_ne!(detect_flavor("_ZN3foo3barE"), SymbolFlavor::Unknown);
        // MSVC patterns vary; basic detection is best-effort and optional.
    }
}
