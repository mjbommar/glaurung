//! Architecture register spelling shared by diagnostics and source projection.

/// Recognise raw register spellings from every architecture the lifter accepts.
///
/// This intentionally excludes Glaurung role names (`argN`, `varN`, `ret`) and
/// recovered storage names. A hit means emitted C still exposes machine storage
/// as a source-level local, which is a quality warning even when definition
/// verification can prove the value safe.
pub(crate) fn is_machine_register_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let name = lower.split('#').next().unwrap_or(&lower);
    if matches!(
        name,
        "rax"
            | "rbx"
            | "rcx"
            | "rdx"
            | "rsi"
            | "rdi"
            | "rbp"
            | "rsp"
            | "rip"
            | "eax"
            | "ebx"
            | "ecx"
            | "edx"
            | "esi"
            | "edi"
            | "ebp"
            | "esp"
            | "eip"
            | "ax"
            | "bx"
            | "cx"
            | "dx"
            | "si"
            | "di"
            | "bp"
            | "sp"
            | "al"
            | "ah"
            | "bl"
            | "bh"
            | "cl"
            | "ch"
            | "dl"
            | "dh"
            | "lr"
            | "pc"
            | "fp"
            | "ip"
            | "xzr"
            | "wzr"
            | "rflags"
            | "eflags"
            | "flags"
            | "cpsr"
            | "apsr"
            | "fpscr"
            | "nzcv"
            | "cs"
            | "ds"
            | "es"
            | "fs"
            | "gs"
            | "ss"
    ) {
        return true;
    }
    numbered(name, "r", 15, &["", "d", "w", "b"])
        || numbered(name, "x", 30, &[""])
        || numbered(name, "w", 30, &[""])
        || numbered(name, "xmm", 31, &[""])
        || numbered(name, "ymm", 31, &[""])
        || numbered(name, "zmm", 31, &[""])
        || numbered(name, "st", 7, &[""])
        || numbered(name, "mm", 7, &[""])
        || numbered(name, "k", 7, &[""])
        || numbered(name, "bnd", 3, &[""])
        || numbered(name, "cr", 15, &[""])
        || numbered(name, "dr", 15, &[""])
        || numbered(name, "v", 31, &[""])
        || numbered(name, "q", 31, &[""])
        || numbered(name, "d", 31, &[""])
        || numbered(name, "s", 31, &[""])
        || numbered(name, "h", 31, &[""])
        || numbered(name, "b", 31, &[""])
        || numbered(name, "z", 31, &[""])
        || numbered(name, "p", 15, &[""])
}

fn numbered(name: &str, prefix: &str, max: u8, suffixes: &[&str]) -> bool {
    let Some(rest) = name.strip_prefix(prefix) else {
        return false;
    };
    suffixes.iter().any(|suffix| {
        rest.strip_suffix(suffix)
            .filter(|digits| !digits.is_empty())
            .and_then(|digits| digits.parse::<u8>().ok())
            .is_some_and(|index| index <= max)
    })
}
