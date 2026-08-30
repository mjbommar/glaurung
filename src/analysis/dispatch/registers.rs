//! Register-name canonicalisation for the dispatch tracker.
//!
//! Every dataflow fact in [`super::DispatchTracker`] is keyed on a register
//! name, and `observe` runs on every instruction of every block in CFG
//! discovery, so these three functions are the hottest string handling in the
//! discovery phase. They live here rather than in `dispatch.rs` because
//! canonicalisation is a self-contained concern with its own equivalence tests,
//! and because the parent module is at the roadmap's 1,000-line ceiling.

use std::borrow::Cow;

/// x86 register aliases, narrowed to the 64-bit parent so `%eax` and `%rax` are
/// one location. Dispatch sequences mix widths freely — clang's `movslq` writes
/// the 64-bit register while the index arrives in a 32-bit one — and treating
/// them as distinct silently loses the chain.
pub(super) fn canon(reg: &str) -> String {
    canon_ref(reg).into_owned()
}

/// [`canon`] without the allocation.
///
/// `canon` is called several times per observed instruction — the store, load
/// and copy arms of `DispatchTracker::observe_instruction` each canonicalise two
/// or three register names — and `observe` runs on every instruction of every
/// block in CFG discovery. The original body allocated twice for every call
/// (`to_ascii_lowercase`, then `to_string` on the matched parent) even when the
/// answer was one of sixteen fixed strings.
///
/// Every result here is either a `'static` name or a borrow of the caller's own
/// slice, so a *lookup* costs nothing; only the sites that insert a map key pay
/// for an owned `String`, via [`canon`]. The uppercase path still allocates,
/// because lowercasing has to produce a new string — but both decoders emit
/// lowercase register names, so it is not the path that runs.
///
/// `canon_ref_agrees_with_the_allocating_form` below pins this against a
/// verbatim copy of the original body.
pub(super) fn canon_ref(reg: &str) -> Cow<'_, str> {
    let stripped = reg.trim_start_matches('%');
    if stripped.bytes().any(|b| b.is_ascii_uppercase()) {
        // Rare: lowercasing must allocate, so re-enter on the lowered copy.
        return Cow::Owned(canon_ref(&stripped.to_ascii_lowercase()).into_owned());
    }
    if let Some(parent) = gp_parent(stripped) {
        return Cow::Borrowed(parent);
    }
    // r0..r15 and their d/w/b views, on x86-64 and ARM alike: the canonical name
    // is the `r` plus the leading digit run, which is a prefix of the input.
    if stripped.starts_with('r') {
        let digits = stripped[1..].bytes().take_while(u8::is_ascii_digit).count();
        if digits > 0 {
            return Cow::Borrowed(&stripped[..1 + digits]);
        }
    }
    Cow::Borrowed(stripped)
}

/// The 64-bit parent of a lowercase, `%`-free x86 general-purpose register name.
fn gp_parent(r: &str) -> Option<&'static str> {
    Some(match r {
        "rax" | "eax" | "ax" | "al" | "ah" => "rax",
        "rbx" | "ebx" | "bx" | "bl" | "bh" => "rbx",
        "rcx" | "ecx" | "cx" | "cl" | "ch" => "rcx",
        "rdx" | "edx" | "dx" | "dl" | "dh" => "rdx",
        "rsi" | "esi" | "si" | "sil" => "rsi",
        "rdi" | "edi" | "di" | "dil" => "rdi",
        "rbp" | "ebp" | "bp" | "bpl" => "rbp",
        "rsp" | "esp" | "sp" | "spl" => "rsp",
        _ => return None,
    })
}

/// `s` lowercased, borrowing it unchanged when it already is.
///
/// `observe_instruction` lowercased the mnemonic on every instruction it saw.
/// Both decoders already emit lowercase mnemonics, so that was an allocation and
/// a copy to produce a string equal to its input; when it is not (a
/// Python-constructed `Instruction`, say) this still lowercases exactly as
/// before.
pub(super) fn ascii_lower(s: &str) -> Cow<'_, str> {
    if s.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(s.to_ascii_lowercase())
    } else {
        Cow::Borrowed(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The allocating body [`canon`]/[`canon_ref`] replaced, kept verbatim as the
    /// oracle. Every register name the tracker sees is canonicalised through the
    /// new form, and every dataflow fact in the dispatch module is keyed on the
    /// result, so a divergence would silently repartition the maps.
    fn canon_original(reg: &str) -> String {
        let r = reg.trim_start_matches('%').to_ascii_lowercase();
        let full = match r.as_str() {
            "rax" | "eax" | "ax" | "al" | "ah" => "rax",
            "rbx" | "ebx" | "bx" | "bl" | "bh" => "rbx",
            "rcx" | "ecx" | "cx" | "cl" | "ch" => "rcx",
            "rdx" | "edx" | "dx" | "dl" | "dh" => "rdx",
            "rsi" | "esi" | "si" | "sil" => "rsi",
            "rdi" | "edi" | "di" | "dil" => "rdi",
            "rbp" | "ebp" | "bp" | "bpl" => "rbp",
            "rsp" | "esp" | "sp" | "spl" => "rsp",
            other => {
                if let Some(rest) = other.strip_prefix('r') {
                    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if !digits.is_empty() {
                        return format!("r{digits}");
                    }
                }
                return other.to_string();
            }
        };
        full.to_string()
    }

    #[test]
    fn canon_ref_agrees_with_the_allocating_form() {
        // Every x86-64 sub-register spelling either decoder emits, the ARM
        // register file (which reaches the same `r`+digits rule), AT&T `%`
        // prefixes, uppercase, and names that must fall through unchanged.
        let mut names: Vec<String> = Vec::new();
        for stem in [
            "rax", "eax", "ax", "al", "ah", "rbx", "ebx", "bx", "bl", "bh", "rcx", "ecx", "cx",
            "cl", "ch", "rdx", "edx", "dx", "dl", "dh", "rsi", "esi", "si", "sil", "rdi", "edi",
            "di", "dil", "rbp", "ebp", "bp", "bpl", "rsp", "esp", "sp", "spl", "rip", "pc", "lr",
            "xmm0", "xmm15", "ymm3", "zmm7", "st0", "es", "ds", "cs", "", "r", "rz", "x0", "w0",
            "v31", "q7", "s3", "d12", "fp",
        ] {
            names.push(stem.to_string());
        }
        for i in 0..=31u32 {
            for suffix in ["", "d", "w", "b"] {
                names.push(format!("r{i}{suffix}"));
            }
        }
        let mut variants: Vec<String> = Vec::new();
        for name in &names {
            variants.push(name.clone());
            variants.push(format!("%{name}"));
            variants.push(format!("%%{name}"));
            variants.push(name.to_ascii_uppercase());
            variants.push(format!("%{}", name.to_ascii_uppercase()));
        }
        for name in &variants {
            assert_eq!(
                canon_ref(name).as_ref(),
                canon_original(name).as_str(),
                "canon_ref diverged on {name:?}"
            );
            assert_eq!(
                canon(name),
                canon_original(name),
                "canon diverged on {name:?}"
            );
        }
        assert!(variants.len() > 400, "grid shrank: {}", variants.len());
    }

    #[test]
    fn ascii_lower_matches_to_ascii_lowercase() {
        for s in [
            "mov", "MOV", "MoV", "cmp", "movzx", "add.w", "IT", "ldr.n", "", "j", "vpaddd",
        ] {
            assert_eq!(ascii_lower(s).as_ref(), s.to_ascii_lowercase().as_str());
        }
        // Borrowed, not copied, when it is already lowercase.
        assert!(matches!(ascii_lower("mov"), Cow::Borrowed(_)));
        assert!(matches!(ascii_lower("MOV"), Cow::Owned(_)));
    }
}
