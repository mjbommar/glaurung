//! COFF-specific rules for the archive signature builder.
//!
//! # Why COFF needed its own rules at all
//!
//! The builder was written against ELF and inherited four ELF-shaped
//! assumptions. Three are harmless on COFF; the first is fatal.
//!
//! 1. **Symbols have sizes.** They do not. An ELF `STT_FUNC` carries
//!    `st_size`; a COFF symbol record has no size field at all. The MS spec's
//!    aux *function definition* record has a `TotalSize`, but GCC writes it
//!    as zero -- measured on `/usr/x86_64-w64-mingw32/lib/libmingwex.a`,
//!    **every** function symbol reports `size() == 0` through the `object`
//!    crate. The builder's `sym.size() < min_function_len` guard therefore
//!    rejected every function in every COFF member, which is why three MinGW
//!    archives returned `raw=0` while `libc.a` returned 4,375. Extent has to
//!    be derived the way FLIRT's own `pcf` does it: the next symbol in the
//!    same section, or the section end.
//! 2. **`SymbolKind::Text` means "function".** It happens to work: `object`
//!    maps `IMAGE_SYM_DTYPE_FUNCTION` to `SymbolKind::Text` for both
//!    `IMAGE_SYM_CLASS_EXTERNAL` and `IMAGE_SYM_CLASS_STATIC`, so both
//!    published and file-local functions are picked up, while the section
//!    definition symbols (`.text`, `.rdata`, ...) come back as
//!    `SymbolKind::Section` and are excluded.
//! 3. **`.text` is one section.** It is not, and it does not have to be: the
//!    builder keys everything on the symbol's own section index, so MSVC's
//!    `/Gy` COMDAT `.text$mn` sections (one function per section) and GCC's
//!    `-ffunction-sections` work unchanged.
//! 4. **Relocations are ELF relocations.** `object` already reports COFF
//!    relocation widths correctly in bits -- 32 for `REL32`, `ADDR32`,
//!    `ADDR32NB` and `SECREL`, 64 for `ADDR64` -- so the generic
//!    `[offset, offset + size/8)` span is right. **No COFF relocation is
//!    linker-relaxable**, so unlike ELF's `R_386_GOT32X` there is no
//!    surrounding opcode pair to widen the mask over.
//!
//! # Names
//!
//! x86-64 COFF uses undecorated C names, so a `libmingwex.a` symbol is
//! literally `cacos`. i386 COFF prefixes cdecl symbols with a single
//! underscore, so the same function is `_cacos` there, and an import thunk is
//! `__imp__cacos`. [`undecorate`] removes exactly that one underscore -- from
//! the name proper, and from the tail of an `__imp_` prefix -- so that an
//! i386 library and an x86-64 library built from the same source name their
//! functions identically, and so a recovered name is the name an analyst
//! types.

use std::borrow::Cow;

use object::{Architecture, BinaryFormat};

/// The `__imp_` prefix a COFF import thunk carries.
///
/// MinGW emits `__imp_foo` (x86-64) / `__imp__foo` (i386) for a reference
/// that goes through an import address table entry rather than a direct call.
/// It is kept as a reference name -- it identifies *which* DLL export the
/// function reaches -- rather than being rewritten to `foo`, because the
/// indirection is real: a resolver looking at a linked image sees the IAT
/// slot, not the target.
const IMP_PREFIX: &str = "__imp_";

/// Strip the i386 cdecl underscore decoration from a COFF symbol name.
///
/// A no-op for every other `(format, architecture)` pair: x86-64, ARM and
/// AArch64 COFF are undecorated, and ELF never had the prefix.
pub(super) fn undecorate(format: BinaryFormat, arch: Architecture, name: &str) -> Cow<'_, str> {
    if format != BinaryFormat::Coff || arch != Architecture::I386 {
        return Cow::Borrowed(name);
    }
    if let Some(rest) = name.strip_prefix(IMP_PREFIX) {
        return match rest.strip_prefix('_') {
            Some(bare) if !bare.is_empty() => Cow::Owned(format!("{IMP_PREFIX}{bare}")),
            _ => Cow::Borrowed(name),
        };
    }
    match name.strip_prefix('_') {
        Some(bare) if !bare.is_empty() => Cow::Borrowed(bare),
        _ => Cow::Borrowed(name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn i386_coff_loses_exactly_one_underscore() {
        let u = |n| undecorate(BinaryFormat::Coff, Architecture::I386, n).into_owned();
        assert_eq!(u("_cacos"), "cacos");
        // `__mingw_vfprintf` decorates to `___mingw_vfprintf`; one underscore
        // comes off, not all of them.
        assert_eq!(u("___mingw_vfprintf"), "__mingw_vfprintf");
        // A name that is only an underscore, or carries none, is left alone
        // rather than turned into the empty string.
        assert_eq!(u("_"), "_");
        assert_eq!(u("cacos"), "cacos");
    }

    #[test]
    fn an_i386_import_thunk_undecorates_inside_the_imp_prefix() {
        let u = |n| undecorate(BinaryFormat::Coff, Architecture::I386, n).into_owned();
        assert_eq!(u("__imp__GetLastError"), "__imp_GetLastError");
        // Already-undecorated, and the degenerate `__imp__`, survive intact.
        assert_eq!(u("__imp_GetLastError"), "__imp_GetLastError");
        assert_eq!(u("__imp__"), "__imp__");
    }

    #[test]
    fn nothing_else_is_decorated() {
        assert_eq!(
            undecorate(BinaryFormat::Coff, Architecture::X86_64, "_cacos"),
            "_cacos"
        );
        assert_eq!(
            undecorate(BinaryFormat::Elf, Architecture::I386, "_cacos"),
            "_cacos"
        );
    }
}
