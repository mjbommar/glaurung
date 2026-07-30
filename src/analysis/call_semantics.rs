//! Source-independent control-flow facts for well-known imported calls.
//!
//! Function discovery runs before AST lowering and prototype recovery, but it
//! still has to know that an imported `exit` does not have a fallthrough edge.
//! Otherwise a stripped binary's linear sweep decodes alignment and the next
//! function as part of the caller.  Keep this small set of exact, ABI-independent
//! flow facts in the analysis layer so CFG recovery and later IR consumers can
//! share it without making function boundaries depend on source debug metadata.

use std::collections::HashSet;

/// Calls whose platform contracts guarantee that control never returns to the
/// instruction after the call.
///
/// Keep this list deliberately conservative.  It contains standardized process
/// termination, checked-failure, unwinding, and Windows fail-fast entry points;
/// project-local helpers require stronger evidence than their spelling alone.
const KNOWN_NORETURN_SYMBOLS: &[&str] = &[
    "_Exit",
    "_Unwind_Resume",
    "__assert_fail",
    "__cxa_rethrow",
    "__cxa_throw",
    "__fastfail",
    "__fortify_fail",
    "__stack_chk_fail",
    "_exit",
    "_invoke_watson",
    "abort",
    "exit",
    "ExitProcess",
    "ExitThread",
    "FatalExit",
    "longjmp",
    "pthread_exit",
    "quick_exit",
    "RaiseFailFastException",
    "RtlExitUserProcess",
    "RtlExitUserThread",
    "siglongjmp",
];

/// Normalize import decorations while retaining meaningful leading
/// underscores (`_exit` and `_Exit` are real C/POSIX names).
fn normalized_import_name(name: &str) -> &str {
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
    clean = clean.strip_suffix(".plt").unwrap_or(clean);
    if let Some((base, suffix)) = clean.rsplit_once('@') {
        if suffix.eq_ignore_ascii_case("plt")
            || suffix.starts_with("GLIBC_")
            || suffix.chars().all(|ch| ch.is_ascii_digit())
        {
            clean = base.trim_end_matches('@');
        }
    }
    clean
}

/// Whether a resolved import name has an authoritative non-returning contract.
pub(crate) fn is_known_noreturn_symbol(name: &str) -> bool {
    let clean = normalized_import_name(name);
    KNOWN_NORETURN_SYMBOLS
        .iter()
        .any(|candidate| clean == *candidate)
}

/// Resolve every imported non-returning call target available in `data`.
///
/// The maps are format-specific because a call instruction targets a local PLT
/// or import-thunk VA, not the unresolved external symbol itself.  No binary is
/// executed; this is static relocation/import-table parsing only.
pub(crate) fn imported_noreturn_targets(data: &[u8]) -> HashSet<u64> {
    let mut targets = HashSet::new();
    let mut consider = |va: u64, name: String| {
        if is_known_noreturn_symbol(&name) {
            targets.insert(va);
        }
    };
    for (va, name) in crate::analysis::elf_plt::elf_plt_map(data) {
        consider(va, name);
    }
    for (va, name) in crate::analysis::pe_iat::pe_import_thunk_map(data) {
        consider(va, name);
    }
    for (va, name) in crate::analysis::macho_stubs::macho_stubs_map(data) {
        consider(va, name);
    }
    targets
}

#[cfg(test)]
mod tests {
    use super::is_known_noreturn_symbol;

    #[test]
    fn recognizes_only_exact_noreturn_import_names_after_decorations() {
        for name in [
            "exit",
            "exit@plt",
            "exit@@GLIBC_2.2.5",
            "__imp_ExitProcess",
            "kernel32!RaiseFailFastException",
            "_Unwind_Resume",
        ] {
            assert!(is_known_noreturn_symbol(name), "{name}");
        }
        for name in [
            "atexit",
            "on_exit",
            "exit_handler",
            "project::exit_now",
            "EXIT",
            "Abort",
        ] {
            assert!(!is_known_noreturn_symbol(name), "{name}");
        }
    }
}
