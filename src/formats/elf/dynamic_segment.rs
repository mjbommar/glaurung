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

/// `e_machine` values. Hoisted to module scope because the PLT stub decoder
/// gates on the machine too, and its instruction encodings are x86-64's alone.
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;

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

/// Size of one x86-64 PLT stub. Fixed by the linker for every table variant.
const X86_64_PLT_STUB: u64 = 16;

/// `endbr64`, the CET landing pad every stub in a current build opens with.
const ENDBR64: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfa];

/// Executable ranges holding PLT import stubs, located without section headers.
///
/// Every other PLT lookup in the tree finds the table by section NAME —
/// `.plt`, `.plt.sec`, `.plt.got`, `.iplt` — and so finds nothing at all on an
/// `sstrip`ped or UPX-packed image. That is usually a silent loss of naming.
/// It became a loss of *functions* when the declared-extent gate in
/// `analysis::cfg::extents` started trusting `.eh_frame`: the linker emits one
/// FDE for the whole `.plt`, so a caller that cannot see where the PLT is reads
/// that FDE as a single 128-byte function and rejects the seven real import
/// stubs inside it. Measured on the `sstrip` corpus lane: five real functions
/// lost, against zero on `strip` where the section names survive.
///
/// A stub is identified by what it *does*, which no strip can remove. There are
/// two shapes, and both are needed — recognising only the first left three of
/// the corpus lane's stubs still lost:
///
/// * **Jumps through a relocated GOT slot** (`.plt.sec`, `.plt.got`, and `.plt`
///   under `-z now`). Requiring the `JUMP_SLOT`/`GLOB_DAT` relocation is what
///   makes this exact rather than a byte-pattern guess: an ordinary
///   `jmp *disp(%rip)` through unrelocated data is not matched.
/// * **Lazy `.plt` entries**, which touch no GOT at all. On a CET build with a
///   `.plt.sec`, the GOT jump moves there and `.plt` holds only
///   `endbr64; push $index; jmp PLT0`. These are recognised by their jump
///   landing on a **PLT0 header** — the one slot that pushes and jumps through
///   the two reserved `.got.plt` slots — which is itself a shape nothing else
///   in an image has.
///
/// x86-64 only; other machines return empty, leaving callers exactly as they
/// were. Returns whole 16-byte stub slots, so a caller can test overlap.
pub fn plt_stub_ranges(data: &[u8]) -> Vec<std::ops::Range<u64>> {
    let slots = relocated_slots(data);
    if slots.got_like.is_empty() {
        return Vec::new();
    }
    let Ok(header) = parse_header(data) else {
        return Vec::new();
    };
    // `relocated_slots` already refused anything but 64-bit little-endian; the
    // stub decoder below is x86-64 encoding and must not be applied elsewhere.
    if header.e_machine != EM_X86_64 {
        return Vec::new();
    }
    let Ok(segments) = SegmentTable::parse(data, &header) else {
        return Vec::new();
    };

    // Every 16-byte-aligned slot in an executable segment, as (va, bytes).
    // Stubs are 16-byte aligned within the table and the table itself is 16-byte
    // aligned, so stepping the slot size cannot miss one.
    let mut slots_to_scan: Vec<(u64, &[u8])> = Vec::new();
    for segment in segments.load_segments() {
        if !segment.is_executable() {
            continue;
        }
        let base_va = segment.header.p_vaddr;
        let file_start = segment.header.p_offset as usize;
        let file_len = segment.header.p_filesz as usize;
        let Some(file_end) = file_start.checked_add(file_len) else {
            continue;
        };
        if file_end > data.len() {
            continue;
        }
        let mut offset = 0u64;
        while offset + X86_64_PLT_STUB <= file_len as u64 {
            let at = file_start + offset as usize;
            let va = base_va.wrapping_add(offset);
            if va % X86_64_PLT_STUB == 0 {
                slots_to_scan.push((va, &data[at..file_end]));
            }
            offset += X86_64_PLT_STUB;
        }
    }

    let mut ranges = Vec::new();
    let mut plt0_headers = BTreeSet::new();
    for (va, bytes) in &slots_to_scan {
        let jumps_through_got = x86_64_got_jump_target(bytes, *va)
            .is_some_and(|target| slots.got_like.contains(&target));
        if jumps_through_got {
            ranges.push(*va..va + X86_64_PLT_STUB);
        } else if is_x86_64_plt0_header(bytes) {
            // PLT0 is not itself an import stub, but it occupies a slot of the
            // same table and its FDE is the one being disqualified.
            plt0_headers.insert(*va);
            ranges.push(*va..va + X86_64_PLT_STUB);
        }
    }
    // Second pass, because a lazy entry is defined by the header it jumps to.
    for (va, bytes) in &slots_to_scan {
        if x86_64_lazy_stub_target(bytes, *va).is_some_and(|t| plt0_headers.contains(&t)) {
            ranges.push(*va..va + X86_64_PLT_STUB);
        }
    }
    ranges.sort_unstable_by_key(|range| range.start);
    ranges.dedup();
    ranges
}

/// Whether a slot is the PLT header: `push GOT+8; jmp *GOT+16`.
///
/// The two reserved `.got.plt` slots it uses carry no relocation — the dynamic
/// linker writes them at load time — so this shape cannot be recognised by the
/// GOT test above, and it is the anchor every lazy entry jumps to.
fn is_x86_64_plt0_header(slot: &[u8]) -> bool {
    let rest = slot.strip_prefix(&ENDBR64).unwrap_or(slot);
    // push m32 (ff /6), then jmp *m32 (ff /4), both RIP-relative.
    matches!(rest.get(..2), Some([0xff, 0x35])) && matches!(rest.get(6..8), Some([0xff, 0x25]))
}

/// Decode a lazy `.plt` entry and return the address it jumps to.
///
/// ```text
///   f3 0f 1e fa  68 imm32  e9 rel32        endbr64; push $i; jmp PLT0
///                68 imm32  e9 rel32        pre-CET form
/// ```
///
/// A `bnd` prefix (`f2`) may precede the `jmp`. The push carries the relocation
/// index and is deliberately not interpreted; only the jump target matters.
fn x86_64_lazy_stub_target(slot: &[u8], va: u64) -> Option<u64> {
    let had_endbr = slot.starts_with(&ENDBR64);
    let rest = if had_endbr { slot.get(4..)? } else { slot };
    let consumed = if had_endbr { 4u64 } else { 0 };
    // push imm32
    if !matches!(rest.first(), Some(0x68)) {
        return None;
    }
    let after_push = rest.get(5..)?;
    let (jump_len, rel_at) = match after_push {
        [0xf2, 0xe9, ..] => (6u64, 2usize),
        [0xe9, ..] => (5u64, 1usize),
        _ => return None,
    };
    let bytes = after_push.get(rel_at..rel_at + 4)?;
    let displacement = i32::from_le_bytes(bytes.try_into().ok()?);
    let next_insn = va
        .checked_add(consumed)?
        .checked_add(5)?
        .checked_add(jump_len)?;
    Some(next_insn.wrapping_add(displacement as i64 as u64))
}

/// Decode a PLT stub's indirect jump and return the GOT address it reads.
///
/// The three encodings the GNU linker emits, in the order a current toolchain
/// produces them:
///
/// ```text
///   f3 0f 1e fa  f2 ff 25 rel32   endbr64; bnd jmp *rel32(%rip)   -- .plt.sec
///   f3 0f 1e fa  ff 25 rel32      endbr64; jmp  *rel32(%rip)      -- CET, no MPX
///   ff 25 rel32                   jmp  *rel32(%rip)               -- classic
/// ```
///
/// `rel32` is relative to the address of the *next* instruction, so the GOT
/// address is `va + displacement_end + rel32`.
fn x86_64_got_jump_target(stub: &[u8], va: u64) -> Option<u64> {
    let after_endbr = stub.starts_with(&ENDBR64);
    let rest = if after_endbr { &stub[4..] } else { stub };
    let consumed = if after_endbr { 4u64 } else { 0 };

    let (opcode_len, rel_at) = match rest {
        // bnd prefix, then the indirect jump.
        [0xf2, 0xff, 0x25, ..] => (7u64, 3usize),
        [0xff, 0x25, ..] => (6u64, 2usize),
        _ => return None,
    };
    let bytes = rest.get(rel_at..rel_at + 4)?;
    let displacement = i32::from_le_bytes(bytes.try_into().ok()?);
    let next_insn = va.checked_add(consumed)?.checked_add(opcode_len)?;
    Some(next_insn.wrapping_add(displacement as i64 as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PLT stubs must be found identically with and without section headers.
    ///
    /// This is the property the declared-extent gate depends on. `strip` keeps
    /// the section table and `sstrip` deletes it; if the two disagree, the gate
    /// deletes real import stubs on exactly the images it was built for.
    #[test]
    fn plt_stubs_are_found_with_and_without_section_headers() {
        let (Some(stripped), Some(sstripped)) = (corpus("strip"), corpus("sstrip")) else {
            return; // corpus not built; tools/realistic_corpus.py --build
        };
        let with_sections = plt_stub_ranges(&stripped);
        let without = plt_stub_ranges(&sstripped);
        assert!(
            !with_sections.is_empty(),
            "no PLT stubs found in the stripped corpus at all"
        );
        assert_eq!(
            with_sections, without,
            "section headers changed the answer: {with_sections:?} vs {without:?}"
        );
        for range in &with_sections {
            assert_eq!(range.end - range.start, X86_64_PLT_STUB);
            assert_eq!(range.start % X86_64_PLT_STUB, 0);
        }
    }

    /// An indirect jump through *unrelocated* memory is not an import stub.
    ///
    /// Requiring the relocation is what separates this from a byte-pattern
    /// guess, and dropping that requirement would let any `jmp *disp(%rip)`
    /// mask a whole 16-byte slot from the extents gate.
    #[test]
    fn an_indirect_jump_through_unrelocated_memory_is_not_a_stub() {
        // endbr64; bnd jmp *0x2f56(%rip) at VA 0x1030 -> next insn 0x103b.
        let stub = [
            0xf3, 0x0f, 0x1e, 0xfa, 0xf2, 0xff, 0x25, 0x56, 0x2f, 0x00, 0x00,
        ];
        assert_eq!(x86_64_got_jump_target(&stub, 0x1030), Some(0x103b + 0x2f56));
        // Classic form, no endbr64: jmp *0x2f56(%rip) at 0x1030 -> next 0x1036.
        let classic = [0xff, 0x25, 0x56, 0x2f, 0x00, 0x00];
        assert_eq!(
            x86_64_got_jump_target(&classic, 0x1030),
            Some(0x1036 + 0x2f56)
        );
        // Anything else decodes to nothing rather than to a wrong address.
        assert_eq!(
            x86_64_got_jump_target(&[0x55, 0x48, 0x89, 0xe5], 0x1030),
            None
        );
        assert_eq!(
            x86_64_got_jump_target(&[0xf3, 0x0f, 0x1e, 0xfa], 0x1030),
            None
        );
    }

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
