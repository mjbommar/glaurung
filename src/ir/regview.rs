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
//!   bit offset 8);
//! * a packed dword lane write (`xmm0_d0`..`xmm0_d3`, `v0_d0`..`v0_d3`)
//!   preserves every parent bit outside its own 32-bit window, exactly as `al`
//!   does — the parent is simply 128 bits wide.
//!
//! # Partial definitions
//!
//! The lanes are here because a scalar 32-bit XMM transfer (`movd`, `movss`)
//! lifts as a read or write of ONE lane, and until this table described them they
//! were names with no relation to the whole register. Two independent defects
//! followed from that single gap: `lift_x86::synchronise_xmm_views` has to append
//! a `concat` bridge per instruction precisely because a lane write does not
//! define the parent, and `ir::abi`'s call-result recovery matched only a
//! whole-`xmm0` read, so `call; movd eax,%xmm0` looked like nobody consumed the
//! float result at all.
//!
//! [`ParentDefinition`] is the fact that replaces the guessing: a set of writes
//! covers every bit of a parent, some of them, or none. "Some" is a first-class
//! answer — it is not "unrelated", and per design rule 5 it is not "no effect".

use once_cell::sync::Lazy;

/// Which ISA's register layout to interpret a name under. Names are ambiguous
/// across ISAs (`sp` is 16-bit on x86-64 and 64-bit on AArch64), so the arch is
/// always explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    AArch64,
}

/// Which register bank a view belongs to.
///
/// The two banks are modelled differently by every downstream consumer, so the
/// distinction has to be a fact of the descriptor rather than a name test:
///
/// * a general-purpose view has a 64-bit parent, is lifted as a bit-preserving
///   read-modify-write of that parent (`lift_x86::partial_write_ops`), and is
///   executed by the emulator's 64-bit register cells; while
/// * a vector view is a 32-bit dword lane of a 128-bit parent that this IR
///   scalarises and versions INDEPENDENTLY of the whole register — there is no
///   128-bit cell to read-modify-write, and there is no join in SSA.
///
/// Consumers that model only one bank filter on this instead of pattern
/// matching register names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegBank {
    /// 64-bit general-purpose parents and their sub-register views.
    Gp,
    /// 128-bit packed-vector parents and their scalarised dword lanes.
    Vector,
}

/// One register name's window onto its canonical full-width parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegView {
    /// The register name this view describes (lowercase).
    pub view: &'static str,
    /// Canonical full-width parent register name (may equal `view`).
    pub parent: &'static str,
    /// Bit offset of the view within the parent: 0, 8 for x86 high bytes, or a
    /// multiple of 32 for a packed dword lane.
    pub offset: u16,
    /// Bit width of the view.
    pub width: u16,
    /// Bit width of the canonical parent.
    pub parent_width: u16,
    /// Which register bank the parent belongs to.
    pub bank: RegBank,
}

impl RegView {
    /// This name *is* the canonical parent (a full-width write replaces it).
    pub fn is_parent(&self) -> bool {
        self.offset == 0 && self.width == self.parent_width
    }

    /// Mask of every bit the canonical parent has.
    pub fn parent_span(&self) -> u128 {
        if self.parent_width >= 128 {
            u128::MAX
        } else {
            (1u128 << self.parent_width) - 1
        }
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
    pub fn value_mask(&self) -> u128 {
        let span = if self.width >= 128 {
            u128::MAX
        } else {
            (1u128 << self.width) - 1
        };
        span << self.offset
    }

    /// Mask of the parent bits a write through this view must KEEP.
    ///
    /// Full width keeps nothing (the write replaces everything); a zero-extending
    /// view also keeps nothing (the bits above it are cleared, not preserved); a
    /// partial view keeps every bit outside its window — which for a 64-bit parent
    /// includes bits 32..63.
    pub fn keep_mask(&self) -> u128 {
        if self.is_parent() || self.zero_extends() {
            return 0;
        }
        self.parent_span() & !self.value_mask()
    }

    /// Mask of the parent bits a write through this view leaves in a KNOWN
    /// state — the exact complement of [`RegView::keep_mask`] within the parent.
    ///
    /// This is the fact that distinguishes a total write from a partial one
    /// without inspecting the name. A full-width or zero-extending view defines
    /// the whole parent (`eax` defines all 64 bits of `rax`: the low half from
    /// the value, the high half as zero). A bit-preserving view defines exactly
    /// its own window and says nothing about the rest — `al` defines bits 0..8,
    /// and the dword lane `xmm0_d0` defines bits 0..32 of a 128-bit register.
    pub fn defines_mask(&self) -> u128 {
        self.parent_span() & !self.keep_mask()
    }
}

/// What a set of writes says about the bits of one canonical parent register.
///
/// Design rule 4/5: incompleteness must be representable and must not read as
/// "no effect". A whole-register read of storage that only lane writes have
/// touched is neither a resolved read nor an unrelated one — it is a read of
/// partially defined storage, and this is the type that says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentDefinition {
    /// Every bit of the parent is defined; a whole-register read resolves.
    Complete,
    /// Some bits are defined and some are not. A whole-register read is
    /// explicitly incomplete, not unrelated.
    Partial {
        /// Parent bits the writes define.
        defined: u128,
        /// Parent bits no write defines.
        undefined: u128,
    },
    /// No bit of the parent is defined by these writes.
    Undefined,
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
        bank: RegBank::Gp,
    }
}

/// Names for the generated packed-register rows.
///
/// The vector tables are the descriptor's one GENERATED section: 16 x86-64
/// registers and 32 AArch64 registers, each with four dword lanes, is 240 rows
/// that would otherwise be 240 hand-written string literals to keep in sync with
/// [`crate::ir::types::packed_dword_lane`]. Each static table is built exactly
/// once behind a `Lazy`, so the leak is a bounded one-time cost paid to keep
/// `RegView` a `Copy` type of `&'static str`.
fn interned(name: String) -> &'static str {
    Box::leak(name.into_boxed_str())
}

/// The whole register and its four scalarised dword lanes.
///
/// The lifters represent packed operations as four independent 32-bit lanes
/// (`crate::ir::types::packed_dword_lane`) so ordinary SSA and dataflow can
/// process them without a parallel vector IR. Those lane names describe REAL
/// BITS of the 128-bit register, and describing them here is what makes a
/// `movd`/`movss` a partial definition of the whole register rather than a write
/// to unrelated storage.
fn packed_views(register: &'static str) -> Vec<RegView> {
    let mut out = Vec::with_capacity(5);
    out.push(RegView {
        view: register,
        parent: register,
        offset: 0,
        width: 128,
        parent_width: 128,
        bank: RegBank::Vector,
    });
    for lane in 0..4u16 {
        out.push(RegView {
            view: interned(format!("{register}_d{lane}")),
            parent: register,
            offset: lane * 32,
            width: 32,
            parent_width: 128,
            bank: RegBank::Vector,
        });
    }
    out
}

/// x86-64 SSE register names `xmm0`..`xmm15`.
const XMM_NAMES: [&str; 16] = [
    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10",
    "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
];

/// AArch64 SIMD register names `v0`..`v31`, the spelling `lift_arm64::packed`
/// scalarises through.
static VREG_NAMES: Lazy<Vec<&'static str>> =
    Lazy::new(|| (0..32).map(|i| interned(format!("v{i}"))).collect());

static X86_64: Lazy<Vec<RegView>> = Lazy::new(|| {
    let mut v: Vec<RegView> = X86_64_VIEWS
        .iter()
        .map(|(view, p, off, w)| mk(view, p, *off, *w))
        .collect();
    v.extend(XMM_NAMES.iter().flat_map(|name| packed_views(name)));
    v
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
    v.extend(VREG_NAMES.iter().flat_map(|name| packed_views(name)));
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

/// Every GENERAL-PURPOSE register view of an architecture, in table order.
///
/// The execution engine holds 64-bit cells and has no representation for a
/// 128-bit vector parent, so it builds its register file from this rather than
/// from [`views`]. Filtering here is deliberate and visible: an engine that
/// silently dropped the vector rows from a table it believed was complete is the
/// failure mode this descriptor exists to prevent.
pub fn gp_views(arch: Arch) -> impl Iterator<Item = &'static RegView> {
    views(arch).iter().filter(|v| v.bank == RegBank::Gp)
}

/// Every canonical parent register name of an architecture, in table order.
pub fn parents(arch: Arch) -> impl Iterator<Item = &'static str> {
    views(arch)
        .iter()
        .filter(|v| v.is_parent() && v.view == v.parent)
        .map(|v| v.view)
}

/// The view for a lowercase register `name`, or `None` if the architecture has no
/// such register (system and segment registers are not modelled here).
pub fn view(arch: Arch, name: &str) -> Option<RegView> {
    views(arch).iter().copied().find(|v| v.view == name)
}

/// What the register names in `written` define of the canonical parent `whole`.
///
/// `None` when `whole` is not a canonical full-width register of `arch`. Names
/// belonging to a different parent contribute nothing, which is the point: a
/// write of `xmm1_d0` says exactly as much about `xmm0` as a write of `rbx` does.
///
/// This is the query behind the whole partial-definition rule. A read of `xmm0`
/// after `movd xmm0, eax` is not a read of unrelated storage and it is not a
/// resolved read either — it is [`ParentDefinition::Partial`], with bits 32..127
/// undefined, and a consumer that cannot handle that must fail closed rather than
/// guess (design rules 5 and 8).
pub fn parent_definition<'a, I>(arch: Arch, whole: &str, written: I) -> Option<ParentDefinition>
where
    I: IntoIterator<Item = &'a str>,
{
    let whole = view(arch, whole).filter(RegView::is_parent)?;
    let span = whole.parent_span();
    let defined = written
        .into_iter()
        .filter_map(|name| view(arch, name))
        .filter(|v| v.parent == whole.parent)
        .fold(0u128, |acc, v| acc | v.defines_mask());
    Some(if defined == span {
        ParentDefinition::Complete
    } else if defined == 0 {
        ParentDefinition::Undefined
    } else {
        ParentDefinition::Partial {
            defined,
            undefined: span & !defined,
        }
    })
}

/// Whether `name` is a scalarised dword lane of the whole register `whole`.
///
/// A lane and its whole register are the same storage but NOT the same SSA
/// value: [`ssa_parent`] declines the vector bank, so a definition spelled
/// `xmm0` does not reach a use spelled `xmm0_d0`. A consumer that has to place a
/// definition where a specific read will find it therefore has to ask this,
/// and asking it here is what keeps the lane spelling out of the consumer.
pub fn is_lane_of(arch: Arch, name: &str, whole: &str) -> bool {
    match (view(arch, name), view(arch, whole)) {
        (Some(lane), Some(whole)) => {
            lane.bank == RegBank::Vector
                && !lane.is_parent()
                && whole.is_parent()
                && lane.parent == whole.parent
        }
        _ => false,
    }
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
///
/// The VECTOR bank is declined outright, whole registers included. SSA does not
/// establish a 128-bit vector register's identity from this table at all: the
/// lifters scalarise packed operations into dword lanes that are versioned
/// independently, and there is no read-modify-write lowering that would join
/// them back. Answering `Some("xmm0")` for `xmm0` would be a harmless identity
/// merge, but every caller reads `is_some()` as "this table settles the name's
/// SSA identity" — and for a vector register it does not. What DOES hold is
/// recorded by [`parent_definition`] and [`is_lane_of`] instead.
pub fn ssa_parent(arch: Arch, name: &str) -> Option<&'static str> {
    let v = view(arch, name)?;
    (v.bank == RegBank::Gp && (v.is_parent() || v.zero_extends())).then_some(v.parent)
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
        assert_eq!(
            eax.keep_mask(),
            0,
            "a 32-bit write preserves no parent bits"
        );
        assert_eq!(eax.value_mask(), 0xFFFF_FFFF);
    }

    #[test]
    fn full_width_write_replaces_the_parent() {
        let rax = view(Arch::X86_64, "rax").unwrap();
        assert!(rax.is_parent());
        assert_eq!(rax.keep_mask(), 0);
        assert_eq!(rax.value_mask(), u128::from(u64::MAX));
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

    /// A scalar 32-bit XMM transfer (`movd`/`movss`) lifts as a read or write of
    /// exactly ONE dword lane. Until the view table described those lanes, they
    /// were names unrelated to the whole register — which is the shared root
    /// cause behind both the `synchronise_xmm_views` concat bridge and the
    /// call-result lane special case in `crate::ir::abi`.
    #[test]
    fn a_scalar_xmm_dword_lane_is_a_view_of_its_whole_register() {
        let d0 = view(Arch::X86_64, "xmm0_d0")
            .expect("the destination of `movd xmm0, eax` must be a modelled view");
        assert_eq!(
            (d0.parent, d0.offset, d0.width, d0.parent_width),
            ("xmm0", 0, 32, 128)
        );
        let d3 = view(Arch::X86_64, "xmm15_d3").expect("every lane of every xmm is a view");
        assert_eq!((d3.parent, d3.offset, d3.width), ("xmm15", 96, 32));
        // A lane write keeps every bit outside its own dword — it is a
        // bit-preserving partial write, exactly like `al` is of `rax`.
        assert!(d0.preserves_parent());
        assert!(!d0.zero_extends());
        assert!(!d0.is_parent());
        assert_eq!(d3.value_mask(), 0xFFFF_FFFFu128 << 96);
        assert_eq!(d3.keep_mask(), !(0xFFFF_FFFFu128 << 96));
        // The AArch64 lifter scalarises through the same spelling.
        let v31 = view(Arch::AArch64, "v31_d2").expect("AArch64 lanes are modelled too");
        assert_eq!((v31.parent, v31.offset, v31.width), ("v31", 64, 32));
    }

    /// The rule this whole increment exists to state: one lane write leaves the
    /// whole register PARTIALLY defined, and four of them leave it complete.
    #[test]
    fn a_lane_write_partially_defines_the_whole_register() {
        let low_dword = 0xFFFF_FFFFu128;
        assert_eq!(
            parent_definition(Arch::X86_64, "xmm0", ["xmm0_d0"]),
            Some(ParentDefinition::Partial {
                defined: low_dword,
                undefined: !low_dword,
            }),
            "`movd xmm0, eax` defines 32 of 128 bits — not all of them, and not none"
        );
        assert_eq!(
            parent_definition(
                Arch::X86_64,
                "xmm0",
                ["xmm0_d0", "xmm0_d1", "xmm0_d2", "xmm0_d3"]
            ),
            Some(ParentDefinition::Complete),
            "four lanes tile the register exactly, so a whole-register read resolves"
        );
        assert_eq!(
            parent_definition(Arch::X86_64, "xmm0", ["xmm0"]),
            Some(ParentDefinition::Complete)
        );
        assert_eq!(
            parent_definition(Arch::X86_64, "xmm0", []),
            Some(ParentDefinition::Undefined)
        );
        // Negative control: a different register's lanes say nothing at all.
        assert_eq!(
            parent_definition(Arch::X86_64, "xmm0", ["xmm1_d0", "xmm1_d1", "rax"]),
            Some(ParentDefinition::Undefined)
        );
        // A view name is not a parent name.
        assert_eq!(
            parent_definition(Arch::X86_64, "xmm0_d0", ["xmm0_d0"]),
            None
        );
        assert_eq!(parent_definition(Arch::X86_64, "eax", ["eax"]), None);
    }

    /// `lift_x86::synchronise_xmm_views` appends
    /// `xmm0 = concat(xmm0_d1, xmm0_d0)` after any instruction that writes lane
    /// 0 or 1, and LLIR has no way to spell a partial definition — so that op
    /// claims a TOTAL definition of a 128-bit register from 64 bits of evidence.
    /// The model now says so outright, which is the reason the bridge could
    /// block 16-byte transport recovery until provably-dead bridges were deleted
    /// at the call site.
    #[test]
    fn the_scalar_view_bridge_claims_more_than_its_two_lanes_define() {
        let low_qword = u128::from(u64::MAX);
        assert_eq!(
            parent_definition(Arch::X86_64, "xmm0", ["xmm0_d0", "xmm0_d1"]),
            Some(ParentDefinition::Partial {
                defined: low_qword,
                undefined: !low_qword,
            }),
            "the two lanes every scalar operation can address are half the register"
        );
    }

    /// The same rule already governed the GP bank; stating it in one type is
    /// what makes the vector case ordinary rather than special.
    #[test]
    fn gp_partial_and_total_writes_follow_the_same_definition_rule() {
        assert_eq!(
            parent_definition(Arch::X86_64, "rax", ["eax"]),
            Some(ParentDefinition::Complete),
            "a 32-bit write zero-extends, so it defines all 64 bits"
        );
        assert_eq!(
            parent_definition(Arch::X86_64, "rax", ["al"]),
            Some(ParentDefinition::Partial {
                defined: 0xFF,
                undefined: u128::from(u64::MAX) & !0xFF,
            })
        );
        assert_eq!(
            parent_definition(Arch::X86_64, "rax", ["al", "ah"]),
            Some(ParentDefinition::Partial {
                defined: 0xFFFF,
                undefined: u128::from(u64::MAX) & !0xFFFF,
            }),
            "`al` and `ah` together still leave bits 16..63 undefined"
        );
        // An alias resolves to the storage it names, not to its own spelling.
        assert_eq!(
            parent_definition(Arch::AArch64, "lr", ["x30"]),
            Some(ParentDefinition::Complete)
        );
    }

    /// Generated conformance over every row of both tables: the partial-write
    /// rule must hold for every view, not only the ones with a hand-written test.
    #[test]
    fn every_view_conforms_to_the_partial_write_rule() {
        for arch in [Arch::X86_64, Arch::AArch64] {
            for v in views(arch) {
                assert_eq!(
                    v.keep_mask() | v.defines_mask(),
                    v.parent_span(),
                    "{} keep|defines must cover the parent",
                    v.view
                );
                assert_eq!(
                    v.keep_mask() & v.defines_mask(),
                    0,
                    "{} keep and defines must not overlap",
                    v.view
                );
                if v.preserves_parent() {
                    assert_eq!(
                        v.defines_mask(),
                        v.value_mask(),
                        "a bit-preserving write through {} defines exactly its window",
                        v.view
                    );
                } else {
                    assert_eq!(
                        v.defines_mask(),
                        v.parent_span(),
                        "a total write through {} defines the whole parent",
                        v.view
                    );
                }
                // Every single write is either total or strictly partial —
                // never "unrelated" to the storage it names.
                let single = parent_definition(arch, v.parent, [v.view])
                    .expect("every view's parent is a canonical parent");
                assert_ne!(
                    single,
                    ParentDefinition::Undefined,
                    "a write through {} must define some bit of {}",
                    v.view,
                    v.parent
                );
                assert_eq!(
                    single == ParentDefinition::Complete,
                    !v.preserves_parent(),
                    "{} is complete exactly when it is not bit-preserving",
                    v.view
                );
            }
        }
    }

    /// Generated conformance for the vector bank specifically: the four dword
    /// lanes must tile their parent exactly, and dropping any one of them must
    /// leave a hole of exactly that lane's width.
    #[test]
    fn every_vector_parent_is_exactly_tiled_by_its_four_dword_lanes() {
        for arch in [Arch::X86_64, Arch::AArch64] {
            let vector_parents: Vec<&str> = parents(arch)
                .filter(|p| view(arch, p).is_some_and(|v| v.bank == RegBank::Vector))
                .collect();
            assert_eq!(
                vector_parents.len(),
                if arch == Arch::X86_64 { 16 } else { 32 },
                "{arch:?} vector parent count"
            );
            for parent in vector_parents {
                let lanes: Vec<String> = (0..4).map(|l| format!("{parent}_d{l}")).collect();
                let names: Vec<&str> = lanes.iter().map(String::as_str).collect();
                assert_eq!(
                    parent_definition(arch, parent, names.iter().copied()),
                    Some(ParentDefinition::Complete),
                    "{parent} must be tiled by its four lanes"
                );
                for dropped in 0..4 {
                    let kept: Vec<&str> = names
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| *i != dropped)
                        .map(|(_, n)| *n)
                        .collect();
                    let hole = 0xFFFF_FFFFu128 << (dropped * 32);
                    assert_eq!(
                        parent_definition(arch, parent, kept),
                        Some(ParentDefinition::Partial {
                            defined: !hole,
                            undefined: hole,
                        }),
                        "{parent} without lane {dropped}"
                    );
                }
                assert!(is_lane_of(arch, &lanes[0], parent));
                assert!(!is_lane_of(arch, parent, parent));
            }
        }
    }

    /// Adding the vector bank must not move any SSA identity. `ssa_parent` is
    /// what `ssa::parent64` and `mir::builder` read, so a vector row that
    /// answered it would silently re-version every packed function.
    #[test]
    fn the_vector_bank_settles_no_ssa_identity() {
        for arch in [Arch::X86_64, Arch::AArch64] {
            for v in views(arch).iter().filter(|v| v.bank == RegBank::Vector) {
                assert_eq!(
                    ssa_parent(arch, v.view),
                    None,
                    "{} must keep its own SSA identity",
                    v.view
                );
                // The storage relation still holds, and is where it is stated.
                assert_eq!(parent_of(arch, v.view), Some(v.parent));
            }
        }
        // The GP bank is untouched.
        assert_eq!(ssa_parent(Arch::X86_64, "eax"), Some("rax"));
        assert_eq!(ssa_parent(Arch::X86_64, "al"), None);
        assert_eq!(ssa_parent(Arch::AArch64, "w7"), Some("x7"));
    }

    /// The execution engine has 64-bit cells and no vector cell. Its view of the
    /// descriptor must therefore be the GP bank exactly — and must still be
    /// every GP name, because a name the register file does not know is a write
    /// it silently drops.
    #[test]
    fn the_gp_bank_is_what_the_execution_engine_sees() {
        for arch in [Arch::X86_64, Arch::AArch64] {
            let gp: Vec<&RegView> = gp_views(arch).collect();
            assert!(gp.iter().all(|v| v.parent_width == 64));
            assert_eq!(
                gp.len(),
                views(arch).iter().filter(|v| v.bank == RegBank::Gp).count()
            );
            assert!(gp.iter().any(|v| v.view == "sp"));
            assert!(!gp.iter().any(|v| v.view.starts_with("xmm")));
        }
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
                        v.parent_span(),
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
