//! The single architecture-aware register-view descriptor.
//!
//! A physical register name is a *view* onto a canonical full-width parent: `al`,
//! `ah`, `ax` and `eax` are all windows onto `rax`, and `w0` is a window onto
//! `x0`. Every consumer that reasons about registers needs the same four facts —
//! canonical parent, bit offset, view width, and what a write through the view
//! does to the bits outside it — so those facts live here, once:
//!
//! * [`crate::exec::state`] builds its register file from [`views`], so the
//!   emulator's partial-register semantics are this table's semantics;
//! * [`crate::ir::lift_x86`] uses [`RegView::keep_mask`] / [`RegView::value_mask`]
//!   to lift a sub-register write as a bit-preserving read-modify-write of the
//!   *canonical parent*;
//! * [`crate::ir::ssa`] uses [`parent_of`] to give a register family one SSA
//!   identity, so a value written as `rax` and read as `eax` is one value.
//!
//! Three independent copies of this knowledge previously disagreed. The
//! disagreement was not theoretical: the lifter modelled `mov $0xAA,%al` as a
//! read-modify-write of the 32-bit view `eax` with a 32-bit mask, which — because
//! a 32-bit write zero-extends — silently cleared bits 32..63 of `rax`, while the
//! emulator preserved them. Whenever `rax` held a 64-bit value (any pointer or
//! `long`), the decompilation was wrong.
//!
//! Semantics encoded here (Intel SDM Vol. 1 3.4.1.1, AMD64 APM Vol. 1 3.1,
//! ARM DDI 0487 B1.2.1):
//!
//! * a full-width write replaces the parent;
//! * a 32-bit write ZERO-EXTENDS — bits 32..63 of the parent become 0 (x86-64
//!   `eax`, AArch64 `w0`);
//! * a 16- or 8-bit write PRESERVES every parent bit outside the view, including
//!   the high 32 (x86-64 `ax`, `al`, and the legacy high bytes `ah`..`dh` at
//!   bit offset 8).

use once_cell::sync::Lazy;

/// Which ISA's register layout to interpret a name under. Names are ambiguous
/// across ISAs (`sp` is 16-bit on x86-64 and 64-bit on AArch64), so the arch is
/// always explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    AArch64,
}

/// One register name's window onto its canonical full-width parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegView {
    /// The register name this view describes (lowercase).
    pub view: &'static str,
    /// Canonical full-width parent register name (may equal `view`).
    pub parent: &'static str,
    /// Bit offset of the view within the parent: 0, or 8 for x86 high bytes.
    pub offset: u16,
    /// Bit width of the view.
    pub width: u16,
    /// Bit width of the canonical parent.
    pub parent_width: u16,
}

impl RegView {
    /// This name *is* the canonical parent (a full-width write replaces it).
    pub fn is_parent(&self) -> bool {
        self.offset == 0 && self.width == self.parent_width
    }

    /// A write through this view zero-extends: bits above it become 0 rather than
    /// being preserved. True for 32-bit views of a 64-bit parent on both x86-64
    /// (`eax`) and AArch64 (`w0`).
    pub fn zero_extends(&self) -> bool {
        self.offset == 0 && self.width == 32 && self.parent_width == 64
    }

    /// A write through this view preserves every parent bit outside it — the
    /// 8-/16-bit x86 views, including the high bytes.
    pub fn preserves_parent(&self) -> bool {
        !self.is_parent() && !self.zero_extends()
    }

    /// Mask of the parent bits this view occupies.
    pub fn value_mask(&self) -> u64 {
        let span = if self.width >= 64 {
            u64::MAX
        } else {
            (1u64 << self.width) - 1
        };
        span << self.offset
    }

    /// Mask of the parent bits a write through this view must KEEP.
    ///
    /// Full width keeps nothing (the write replaces everything); a zero-extending
    /// view also keeps nothing (the bits above it are cleared, not preserved); a
    /// partial view keeps every bit outside its window — which for a 64-bit parent
    /// includes bits 32..63.
    pub fn keep_mask(&self) -> u64 {
        if self.is_parent() || self.zero_extends() {
            return 0;
        }
        let parent_span = if self.parent_width >= 64 {
            u64::MAX
        } else {
            (1u64 << self.parent_width) - 1
        };
        parent_span & !self.value_mask()
    }
}

/// x86-64 views: (view, canonical parent, bit offset, width). Every parent is
/// 64-bit wide.
const X86_64_VIEWS: &[(&str, &str, u16, u16)] = &[
    ("rax", "rax", 0, 64),
    ("eax", "rax", 0, 32),
    ("ax", "rax", 0, 16),
    ("al", "rax", 0, 8),
    ("ah", "rax", 8, 8),
    ("rbx", "rbx", 0, 64),
    ("ebx", "rbx", 0, 32),
    ("bx", "rbx", 0, 16),
    ("bl", "rbx", 0, 8),
    ("bh", "rbx", 8, 8),
    ("rcx", "rcx", 0, 64),
    ("ecx", "rcx", 0, 32),
    ("cx", "rcx", 0, 16),
    ("cl", "rcx", 0, 8),
    ("ch", "rcx", 8, 8),
    ("rdx", "rdx", 0, 64),
    ("edx", "rdx", 0, 32),
    ("dx", "rdx", 0, 16),
    ("dl", "rdx", 0, 8),
    ("dh", "rdx", 8, 8),
    ("rsi", "rsi", 0, 64),
    ("esi", "rsi", 0, 32),
    ("si", "rsi", 0, 16),
    ("sil", "rsi", 0, 8),
    ("rdi", "rdi", 0, 64),
    ("edi", "rdi", 0, 32),
    ("di", "rdi", 0, 16),
    ("dil", "rdi", 0, 8),
    ("rbp", "rbp", 0, 64),
    ("ebp", "rbp", 0, 32),
    ("bp", "rbp", 0, 16),
    ("bpl", "rbp", 0, 8),
    ("rsp", "rsp", 0, 64),
    ("esp", "rsp", 0, 32),
    ("sp", "rsp", 0, 16),
    ("spl", "rsp", 0, 8),
    ("r8", "r8", 0, 64),
    ("r8d", "r8", 0, 32),
    ("r8w", "r8", 0, 16),
    ("r8b", "r8", 0, 8),
    ("r9", "r9", 0, 64),
    ("r9d", "r9", 0, 32),
    ("r9w", "r9", 0, 16),
    ("r9b", "r9", 0, 8),
    ("r10", "r10", 0, 64),
    ("r10d", "r10", 0, 32),
    ("r10w", "r10", 0, 16),
    ("r10b", "r10", 0, 8),
    ("r11", "r11", 0, 64),
    ("r11d", "r11", 0, 32),
    ("r11w", "r11", 0, 16),
    ("r11b", "r11", 0, 8),
    ("r12", "r12", 0, 64),
    ("r12d", "r12", 0, 32),
    ("r12w", "r12", 0, 16),
    ("r12b", "r12", 0, 8),
    ("r13", "r13", 0, 64),
    ("r13d", "r13", 0, 32),
    ("r13w", "r13", 0, 16),
    ("r13b", "r13", 0, 8),
    ("r14", "r14", 0, 64),
    ("r14d", "r14", 0, 32),
    ("r14w", "r14", 0, 16),
    ("r14b", "r14", 0, 8),
    ("r15", "r15", 0, 64),
    ("r15d", "r15", 0, 32),
    ("r15w", "r15", 0, 16),
    ("r15b", "r15", 0, 8),
    ("rip", "rip", 0, 64),
    ("eip", "rip", 0, 32),
];

/// Canonical 64-bit AArch64 GPR names `x0`..`x30` and their 32-bit `w` views.
const XREG_NAMES: [&str; 31] = [
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
    "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
    "x28", "x29", "x30",
];
const WREG_NAMES: [&str; 31] = [
    "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8", "w9", "w10", "w11", "w12", "w13", "w14",
    "w15", "w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23", "w24", "w25", "w26", "w27",
    "w28", "w29", "w30",
];

fn mk(view: &'static str, parent: &'static str, offset: u16, width: u16) -> RegView {
    RegView {
        view,
        parent,
        offset,
        width,
        parent_width: 64,
    }
}

static X86_64: Lazy<Vec<RegView>> = Lazy::new(|| {
    X86_64_VIEWS
        .iter()
        .map(|(v, p, off, w)| mk(v, p, *off, *w))
        .collect()
});

/// AArch64 views. `wN` is the zero-extending low half of `xN`; `lr`/`fp` are
/// aliases of `x30`/`x29`; `sp`/`wsp` and `pc` are their own parents. The zero
/// registers (`xzr`/`wzr`) are not views — they read 0 and discard writes — so
/// they are deliberately absent and handled by the consumer.
static AARCH64: Lazy<Vec<RegView>> = Lazy::new(|| {
    let mut v = Vec::with_capacity(2 * 31 + 5);
    for i in 0..31usize {
        v.push(mk(XREG_NAMES[i], XREG_NAMES[i], 0, 64));
        v.push(mk(WREG_NAMES[i], XREG_NAMES[i], 0, 32));
    }
    v.push(mk("sp", "sp", 0, 64));
    v.push(mk("wsp", "sp", 0, 32));
    v.push(mk("lr", "x30", 0, 64));
    v.push(mk("fp", "x29", 0, 64));
    v.push(mk("pc", "pc", 0, 64));
    v
});

/// Canonical spelling of a lowercase register name.
///
/// Disassembler backends disagree on the byte views of the extended registers:
/// iced-x86 prints `r8l`..`r15l`, while the AMD64/Intel manuals, GNU as, LLVM and
/// this descriptor use `r8b`..`r15b`. A name that matches no view is not a
/// harmless spelling difference — writes to it are dropped and reads return zero —
/// so lifters normalise through here before constructing a VReg.
pub fn canonical_name(name: &str) -> String {
    if let Some(num) = name.strip_prefix('r').and_then(|r| r.strip_suffix('l')) {
        if let Ok(n) = num.parse::<u8>() {
            if (8..=15).contains(&n) {
                return format!("r{n}b");
            }
        }
    }
    name.to_string()
}

/// Every register view of an architecture, in table order.
pub fn views(arch: Arch) -> &'static [RegView] {
    match arch {
        Arch::X86_64 => &X86_64,
        Arch::AArch64 => &AARCH64,
    }
}

/// The view for a lowercase register `name`, or `None` if the architecture has no
/// such general-purpose register (vector/system registers are not modelled here).
pub fn view(arch: Arch, name: &str) -> Option<RegView> {
    views(arch).iter().copied().find(|v| v.view == name)
}

/// Canonical full-width parent register name for `name`.
pub fn parent_of(arch: Arch, name: &str) -> Option<&'static str> {
    view(arch, name).map(|v| v.parent)
}

/// The canonical parent a view may share ONE SSA value with, or `None` if it must
/// keep its own identity.
///
/// A full-width view and a zero-extending 32-bit view are total writes: after
/// either, the parent's value is fully determined by the write, so `rax` and `eax`
/// can be versioned as one value and a `%rax` write correctly shadows a later
/// `%eax` read. A bit-preserving view (`al`, `ah`, `ax`) is NOT a total write —
/// its result depends on the parent's previous value — so merging it would claim a
/// definition that does not exist. Those are lifted as explicit read-modify-writes
/// of the parent instead (see `lift_x86::partial_write_ops`), which is what gives
/// the SSA pass a real definition to version.
pub fn ssa_parent(arch: Arch, name: &str) -> Option<&'static str> {
    let v = view(arch, name)?;
    (v.is_parent() || v.zero_extends()).then_some(v.parent)
}

/// Do two names belong to the same register family (same canonical parent)?
pub fn same_family(arch: Arch, a: &str, b: &str) -> bool {
    match (parent_of(arch, a), parent_of(arch, b)) {
        (Some(pa), Some(pb)) => pa == pb,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_low_byte_write_keeps_the_whole_upper_parent() {
        let al = view(Arch::X86_64, "al").unwrap();
        assert_eq!(al.parent, "rax");
        assert_eq!((al.offset, al.width), (0, 8));
        assert_eq!(al.value_mask(), 0xFF);
        // THE bug this descriptor exists to prevent: the keep mask must cover
        // bits 8..63, not just 8..31.
        assert_eq!(al.keep_mask(), 0xFFFF_FFFF_FFFF_FF00);
        assert!(al.preserves_parent());
        assert!(!al.zero_extends());
    }

    #[test]
    fn x86_high_byte_write_addresses_bits_8_to_16() {
        let ah = view(Arch::X86_64, "ah").unwrap();
        assert_eq!((ah.parent, ah.offset, ah.width), ("rax", 8, 8));
        assert_eq!(ah.value_mask(), 0xFF00);
        assert_eq!(ah.keep_mask(), 0xFFFF_FFFF_FFFF_00FF);
    }

    #[test]
    fn x86_word_write_keeps_bits_16_to_63() {
        let ax = view(Arch::X86_64, "ax").unwrap();
        assert_eq!(ax.value_mask(), 0xFFFF);
        assert_eq!(ax.keep_mask(), 0xFFFF_FFFF_FFFF_0000);
    }

    #[test]
    fn x86_32bit_write_zero_extends_and_keeps_nothing() {
        let eax = view(Arch::X86_64, "eax").unwrap();
        assert!(eax.zero_extends());
        assert!(!eax.preserves_parent());
        assert_eq!(eax.keep_mask(), 0, "a 32-bit write preserves no parent bits");
        assert_eq!(eax.value_mask(), 0xFFFF_FFFF);
    }

    #[test]
    fn full_width_write_replaces_the_parent() {
        let rax = view(Arch::X86_64, "rax").unwrap();
        assert!(rax.is_parent());
        assert_eq!(rax.keep_mask(), 0);
        assert_eq!(rax.value_mask(), u64::MAX);
    }

    #[test]
    fn extended_registers_have_all_four_views() {
        for (v, off, w) in [("r8", 0, 64), ("r8d", 0, 32), ("r8w", 0, 16), ("r8b", 0, 8)] {
            let rv = view(Arch::X86_64, v).unwrap();
            assert_eq!((rv.parent, rv.offset, rv.width), ("r8", off, w));
        }
        // r8..r15 have no high-byte view.
        assert!(view(Arch::X86_64, "r8h").is_none());
    }

    #[test]
    fn iced_byte_register_spelling_is_normalised() {
        // iced-x86 prints `R8L`; every other tool (and this table) says `r8b`.
        // Left unnormalised, `r8l` matches no view, so a write to it is silently
        // dropped by the register file.
        for n in 8..=15u8 {
            assert_eq!(canonical_name(&format!("r{n}l")), format!("r{n}b"));
            assert!(view(Arch::X86_64, &canonical_name(&format!("r{n}l"))).is_some());
        }
        // Names that are already canonical, and unrelated names, pass through.
        for name in ["al", "ah", "rax", "r8b", "r8d", "rsp", "x0", "w0", "lr"] {
            assert_eq!(canonical_name(name), name);
        }
        // `rXl` outside the extended range is not a byte-register spelling.
        assert_eq!(canonical_name("r7l"), "r7l");
        assert_eq!(canonical_name("r16l"), "r16l");
    }

    #[test]
    fn families_are_recognised_across_widths_but_not_across_registers() {
        assert!(same_family(Arch::X86_64, "al", "rax"));
        assert!(same_family(Arch::X86_64, "ah", "eax"));
        assert!(!same_family(Arch::X86_64, "al", "bl"));
        assert!(same_family(Arch::AArch64, "w5", "x5"));
        assert!(same_family(Arch::AArch64, "lr", "x30"));
        assert!(!same_family(Arch::AArch64, "w5", "x6"));
    }

    #[test]
    fn sp_is_arch_dependent() {
        // 16-bit view of rsp on x86-64; a 64-bit parent of its own on AArch64.
        let x86_sp = view(Arch::X86_64, "sp").unwrap();
        assert_eq!((x86_sp.parent, x86_sp.width), ("rsp", 16));
        let a64_sp = view(Arch::AArch64, "sp").unwrap();
        assert_eq!((a64_sp.parent, a64_sp.width), ("sp", 64));
    }

    #[test]
    fn aarch64_w_registers_zero_extend_into_their_x_parent() {
        for i in 0..31usize {
            let w = view(Arch::AArch64, WREG_NAMES[i]).unwrap();
            assert_eq!(w.parent, XREG_NAMES[i]);
            assert!(w.zero_extends());
            assert_eq!(w.keep_mask(), 0);
        }
    }

    #[test]
    fn every_view_name_is_unique_and_lowercase() {
        for arch in [Arch::X86_64, Arch::AArch64] {
            let mut seen = std::collections::HashSet::new();
            for v in views(arch) {
                assert!(seen.insert(v.view), "duplicate view {}", v.view);
                assert_eq!(v.view, v.view.to_ascii_lowercase());
                assert!(
                    view(arch, v.parent).map(|p| p.is_parent()).unwrap_or(false),
                    "parent {} of {} is not itself a full-width view",
                    v.parent,
                    v.view
                );
                assert!(v.offset + v.width <= v.parent_width);
            }
        }
    }

    #[test]
    fn masks_partition_the_parent() {
        for arch in [Arch::X86_64, Arch::AArch64] {
            for v in views(arch) {
                if v.preserves_parent() {
                    assert_eq!(
                        v.keep_mask() | v.value_mask(),
                        u64::MAX,
                        "{} keep|value must cover the parent",
                        v.view
                    );
                    assert_eq!(
                        v.keep_mask() & v.value_mask(),
                        0,
                        "{} keep and value must not overlap",
                        v.view
                    );
                }
            }
        }
    }
}
