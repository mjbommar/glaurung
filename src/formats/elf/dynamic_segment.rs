//! Read the dynamic array through `PT_DYNAMIC` rather than through `.dynamic`.
//!
//! Everything else in this module locates the dynamic linking information by
//! **section name** — `parse_dynamic_section` asks for `.dynamic`,
//! `dynamic_symbols` for `.dynsym`, `got_relocations` for `.rela.dyn`,
//! `plt_relocations` for `.rela.plt`. That is fine for a compiler's output and
//! wrong for a great deal of real input, because the section header table is
//! metadata that no loader reads: `execve` follows the program headers. `sstrip`
//! deletes the table outright and UPX emits `e_shnum == 0`, and at that point
//! every one of those lookups returns `None` — not an error, just nothing.
//!
//! The dynamic linker itself never had this problem. It finds the same data
//! through `PT_DYNAMIC`, which survives stripping because the process would not
//! start without it. This module does what the linker does.
//!
//! # Why relocation *type* is the discriminator
//!
//! The immediate consumer is the read-only code-pointer sweep that recovers
//! vtables and function-pointer tables. It has to tell a genuine table of code
//! pointers from the GOT, because on a lazily-bound ELF every GOT slot for an
//! imported function holds a back-pointer into its own PLT stub — an address
//! that is executable, passes a naive "does this look like code?" filter, and is
//! not a function start. On a stripped `getent` that produced 64 phantom
//! functions and zero real ones.
//!
//! Today that distinction is made by section name. Without section names the
//! obvious substitute — "is this slot relocated?" — is **wrong**, and would be
//! worse than no fix at all: in a PIE binary the pointer tables are relocated
//! too, by `R_*_RELATIVE`, because their absolute addresses need rebasing.
//! Excluding every relocated slot would exclude exactly what we are looking for.
//!
//! Measured on a corpus built from our own fixtures:
//!
//! ```text
//! 94  R_X86_64_RELATIVE   .data.rel.ro at 0x4ae0, size 0x2d8 == 91 pointers
//!  5  R_X86_64_GLOB_DAT   .got at 0x4fa8
//!  3  R_X86_64_JUMP_SLOT  .got.plt
//! ```
//!
//! The 91 `RELATIVE` slots in `.data.rel.ro` are precisely the 91 `vtable` seeds
//! that discovery loses when the section headers go. So the rule is: `RELATIVE`
//! marks a table worth reading, `GLOB_DAT`/`JUMP_SLOT` mark the GOT and must be
//! skipped.

use std::collections::BTreeSet;

use super::headers::parse_header;
use super::segments::SegmentTable;
use super::types::{ElfClass, DT_JMPREL, DT_NULL, DT_PLTRELSZ, DT_RELA, DT_RELASZ, PT_DYNAMIC};

/// Size of one `Elf64_Rela`: `r_offset`, `r_info`, `r_addend`.
const RELA64_SIZE: usize = 24;
/// Size of one `Elf64_Dyn`: `d_tag`, `d_un`.
const DYN64_SIZE: usize = 16;

// x86-64. Named here rather than imported because the classification below is
// deliberately per-architecture: the same numeric type means different things
// on different machines, and guessing across architectures is how a scan starts
// trusting the GOT.
const R_X86_64_GLOB_DAT: u32 = 6;
const R_X86_64_JUMP_SLOT: u32 = 7;
const R_X86_64_RELATIVE: u32 = 8;

// AArch64.
const R_AARCH64_GLOB_DAT: u32 = 1025;
const R_AARCH64_JUMP_SLOT: u32 = 1026;
const R_AARCH64_RELATIVE: u32 = 1027;

/// Image addresses grouped by what their relocation says about them.
///
/// Only the two classes a pointer-table scan needs to tell apart are modelled;
/// everything else is deliberately dropped rather than bucketed into a
/// catch-all that a caller might mistake for meaningful.
#[derive(Debug, Default, Clone)]
pub struct RelocatedSlots {
    /// Slots the dynamic linker fills with a resolved symbol address — the GOT.
    /// A pointer-table scan must skip these or it reports PLT stubs as
    /// functions.
    pub got_like: BTreeSet<u64>,
    /// Slots holding a load-address-relative pointer. In a PIE binary this is
    /// what a vtable or a function-pointer table is made of.
    pub relative: BTreeSet<u64>,
}

impl RelocatedSlots {
    /// Whether anything was recovered at all.
    pub fn is_empty(&self) -> bool {
        self.got_like.is_empty() && self.relative.is_empty()
    }
}

/// Classify one relocation type for the machine that produced it.
///
/// Returns `None` for anything not in the two interesting classes, including
/// every type on an architecture this does not model — failing closed, because a
/// misclassified GOT slot resurrects the phantom-function defect while an
/// unclassified table merely goes unread.
fn classify(machine: u16, r_type: u32) -> Option<SlotClass> {
    const EM_X86_64: u16 = 62;
    const EM_AARCH64: u16 = 183;
    let (glob_dat, jump_slot, relative) = match machine {
        EM_X86_64 => (R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT, R_X86_64_RELATIVE),
        EM_AARCH64 => (R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT, R_AARCH64_RELATIVE),
        _ => return None,
    };
    if r_type == glob_dat || r_type == jump_slot {
        Some(SlotClass::GotLike)
    } else if r_type == relative {
        Some(SlotClass::Relative)
    } else {
        None
    }
}

enum SlotClass {
    GotLike,
    Relative,
}

/// Read `(d_tag, d_val)` pairs out of the `PT_DYNAMIC` segment.
fn dynamic_entries(segments: &SegmentTable<'_>) -> Vec<(i64, u64)> {
    let Some(dynamic) = segments
        .segments()
        .find(|segment| segment.header.p_type == PT_DYNAMIC)
    else {
        return Vec::new();
    };
    let bytes = dynamic.data;
    let mut entries = Vec::new();
    let mut offset = 0usize;
    while offset + DYN64_SIZE <= bytes.len() {
        let tag = i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        let value = u64::from_le_bytes(bytes[offset + 8..offset + 16].try_into().unwrap());
        if tag == DT_NULL {
            break;
        }
        entries.push((tag, value));
        offset += DYN64_SIZE;
    }
    entries
}

/// Every relocated slot the dynamic segment describes, classified.
///
/// Works with or without a section header table, because it reads only what the
/// loader reads. Returns an empty set rather than an error for anything it
/// cannot make sense of: this is a fallback path, and a caller that gets nothing
/// back is no worse off than before it existed.
///
/// Currently 64-bit little-endian `RELA` only, which covers x86-64 and AArch64.
/// A 32-bit or `REL` image returns empty rather than a wrong answer.
pub fn relocated_slots(data: &[u8]) -> RelocatedSlots {
    let mut out = RelocatedSlots::default();
    let Ok(header) = parse_header(data) else {
        return out;
    };
    // 64-bit little-endian RELA only; anything else returns empty rather than
    // a wrong answer, which is the whole contract of a fallback path.
    if !header.ident.data.is_little_endian() || header.ident.class != ElfClass::Elf64 {
        return out;
    }
    let Ok(segments) = SegmentTable::parse(data, &header) else {
        return out;
    };

    let entries = dynamic_entries(&segments);
    let get = |wanted: i64| {
        entries
            .iter()
            .find(|(tag, _)| *tag == wanted)
            .map(|(_, v)| *v)
    };

    // DT_RELA covers the ordinary relocations; DT_JMPREL covers the PLT's. Both
    // are needed: the GOT slots we most want to exclude live in the second.
    for (addr_tag, size_tag) in [(DT_RELA, DT_RELASZ), (DT_JMPREL, DT_PLTRELSZ)] {
        let (Some(table_va), Some(table_size)) = (get(addr_tag), get(size_tag)) else {
            continue;
        };
        let Some(start) = segments.vaddr_to_offset(table_va) else {
            continue;
        };
        let Some(end) = start.checked_add(table_size as usize) else {
            continue;
        };
        if end > data.len() {
            continue;
        }
        for entry in data[start..end].chunks_exact(RELA64_SIZE) {
            let r_offset = u64::from_le_bytes(entry[0..8].try_into().unwrap());
            let r_info = u64::from_le_bytes(entry[8..16].try_into().unwrap());
            match classify(header.e_machine, r_info as u32) {
                Some(SlotClass::GotLike) => {
                    out.got_like.insert(r_offset);
                }
                Some(SlotClass::Relative) => {
                    out.relative.insert(r_offset);
                }
                None => {}
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The corpus this was measured on, if it has been built.
    fn corpus(variant: &str) -> Option<Vec<u8>> {
        let path = format!(
            "{}/tests/realistic_corpus/build/corpus.{variant}",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read(path).ok()
    }

    /// The whole point: the same answer with and without section headers.
    ///
    /// `sstrip` removes only the section header table — the loadable segments
    /// and the executable bytes are identical — so any difference between these
    /// two results is this module reading metadata it should not need.
    #[test]
    fn the_same_slots_are_found_with_and_without_a_section_header_table() {
        let (Some(sectioned), Some(sectionless)) = (corpus("strip"), corpus("sstrip")) else {
            eprintln!("corpus not built; run tools/realistic_corpus.py");
            return;
        };
        let with = relocated_slots(&sectioned);
        let without = relocated_slots(&sectionless);
        assert!(
            !with.is_empty(),
            "found no relocations at all on an ordinary stripped binary"
        );
        assert_eq!(
            with.got_like, without.got_like,
            "the GOT must be identifiable without section headers, or the \
             pointer-table scan cannot tell a vtable from a PLT back-pointer"
        );
        assert_eq!(
            with.relative, without.relative,
            "the relative slots are the pointer tables themselves"
        );
    }

    /// The two classes must not be confused, because the fix depends on it.
    ///
    /// If `relative` were empty the scan would find nothing; if `got_like` were
    /// empty it would report PLT stubs as functions. Both failures are silent,
    /// so both are asserted.
    #[test]
    fn the_got_and_the_pointer_tables_are_told_apart() {
        let Some(data) = corpus("sstrip") else {
            eprintln!("corpus not built; run tools/realistic_corpus.py");
            return;
        };
        let slots = relocated_slots(&data);
        assert!(
            !slots.got_like.is_empty(),
            "no GOT slots identified — the exclusion the scan relies on is absent"
        );
        assert!(
            !slots.relative.is_empty(),
            "no relative slots identified — these are the pointer tables"
        );
        assert!(
            slots.got_like.is_disjoint(&slots.relative),
            "a slot cannot be both the GOT and a pointer table"
        );
    }

    /// Nonsense in, empty out — never a panic and never a wrong answer.
    #[test]
    fn malformed_input_yields_nothing_rather_than_a_guess() {
        assert!(relocated_slots(&[]).is_empty());
        assert!(relocated_slots(b"not an elf at all").is_empty());
        assert!(relocated_slots(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]).is_empty());
    }
}
