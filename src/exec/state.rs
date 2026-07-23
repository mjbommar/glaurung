//! Machine register state, generic over the value [`Domain`].
//!
//! The register file follows the flat-guest-state model (VEX/P-code): every
//! physical register is backed by a full-width *canonical* cell, and
//! sub-register reads/writes are expressed as bit `extract`/`concat`/`zext`
//! through the [`Domain`], so partial-register aliasing is structural and
//! correct for both the concrete and symbolic backends.
//!
//! The x86-64 partial-write rules are encoded here, where they belong (the
//! arch's register layout), rather than forcing the lifter to emit explicit
//! extends (this realizes the Phase-0 task-0.7 deferral noted in the plan):
//!
//! * a 64-bit write replaces the whole cell;
//! * a **32-bit write zeroes the upper 32 bits** of the 64-bit parent;
//! * a 16-bit or 8-bit write **preserves** the unaffected high bits;
//! * the legacy high-byte registers (`ah`/`bh`/`ch`/`dh`) write bits `[8:16)`.

use std::borrow::Cow;
use std::collections::HashMap;

use once_cell::sync::Lazy;

use crate::exec::domain::Domain;
use crate::ir::types::{Flag, VReg, Width};

/// Which ISA's register layout a [`RegFile`] uses. Selects how physical register
/// names resolve to canonical cells (and disambiguates names like `sp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegArch {
    X86_64,
    AArch64,
}

/// Number of canonical full-width parent cells (covers x86-64 `rax`..`r15`,`rip`
/// at 0..=16 and AArch64 `x0`..`x30`,`sp`,`pc` at 0..=32).
const NUM_PARENTS: usize = 40;
/// Number of processor flags ([`Flag`] variants).
const NUM_FLAGS: usize = 10;

/// How a physical register name maps onto a canonical full-width cell.
#[derive(Debug, Clone, Copy)]
struct RegSlot {
    /// Index of the canonical full-width parent cell.
    parent: u8,
    /// Bit offset of this view within the parent (0, or 8 for x86 high-byte regs).
    offset: u16,
    /// Bit width of this view.
    width: u16,
}

/// Flag → dense index.
fn flag_idx(f: Flag) -> usize {
    match f {
        Flag::Z => 0,
        Flag::C => 1,
        Flag::Ule => 2,
        Flag::S => 3,
        Flag::Slt => 4,
        Flag::Sle => 5,
        Flag::O => 6,
        Flag::P => 7,
        Flag::A => 8,
        Flag::Bit => 9,
    }
}

/// x86-64 canonical parent register → cell index (`rax`=0..`r15`=15, `rip`=16).
fn x86_64_parent_idx(name: &str) -> Option<u8> {
    Some(match name {
        "rax" => 0,
        "rbx" => 1,
        "rcx" => 2,
        "rdx" => 3,
        "rsi" => 4,
        "rdi" => 5,
        "rbp" => 6,
        "rsp" => 7,
        "r8" => 8,
        "r9" => 9,
        "r10" => 10,
        "r11" => 11,
        "r12" => 12,
        "r13" => 13,
        "r14" => 14,
        "r15" => 15,
        "rip" => 16,
        _ => return None,
    })
}

/// x86-64 register views: (view name, canonical parent name, bit offset, width).
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

/// Name → slot map for x86-64 (built once; O(1) lookup, no allocation/scan).
static X86_64_SLOTS: Lazy<HashMap<&'static str, RegSlot>> = Lazy::new(|| {
    let mut m = HashMap::with_capacity(X86_64_VIEWS.len());
    for (view, parent, offset, width) in X86_64_VIEWS {
        let parent = x86_64_parent_idx(parent).expect("known x86-64 parent");
        m.insert(
            *view,
            RegSlot {
                parent,
                offset: *offset,
                width: *width,
            },
        );
    }
    m
});

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

/// Name → slot map for AArch64. `wN` writes zero-extend the 64-bit parent `xN`;
/// `lr`=x30, `fp`=x29; `sp`/`pc` are their own cells. Zero registers (`xzr`/`wzr`)
/// are handled directly by [`RegFile`].
static AARCH64_SLOTS: Lazy<HashMap<&'static str, RegSlot>> = Lazy::new(|| {
    let mut m = HashMap::new();
    for i in 0..=30u8 {
        m.insert(
            XREG_NAMES[i as usize],
            RegSlot {
                parent: i,
                offset: 0,
                width: 64,
            },
        );
        m.insert(
            WREG_NAMES[i as usize],
            RegSlot {
                parent: i,
                offset: 0,
                width: 32,
            },
        );
    }
    m.insert(
        "sp",
        RegSlot {
            parent: 31,
            offset: 0,
            width: 64,
        },
    );
    m.insert(
        "wsp",
        RegSlot {
            parent: 31,
            offset: 0,
            width: 32,
        },
    );
    m.insert(
        "lr",
        RegSlot {
            parent: 30,
            offset: 0,
            width: 64,
        },
    );
    m.insert(
        "fp",
        RegSlot {
            parent: 29,
            offset: 0,
            width: 64,
        },
    );
    m.insert(
        "pc",
        RegSlot {
            parent: 32,
            offset: 0,
            width: 64,
        },
    );
    m
});

/// Is `name` the AArch64 zero register (reads 0, writes discarded)?
fn is_aarch64_zero_reg(name: &str) -> bool {
    matches!(name, "xzr" | "wzr")
}

/// Lowercase `name` without allocating when it is already lowercase (the common
/// case — the lifter emits lowercase register names).
fn lower(name: &str) -> Cow<'_, str> {
    if name.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(name.to_ascii_lowercase())
    } else {
        Cow::Borrowed(name)
    }
}

/// A register file holding `Domain::Val` cells, with arch-aware sub-register
/// semantics (x86-64 or AArch64). Cells are created lazily (zero on first read).
pub struct RegFile<D: Domain> {
    /// Canonical full-width parent cells, indexed by parent id (see
    /// [`x86_64_parent_idx`]). `None` reads as zero. O(1), no hashing.
    cells: Vec<Option<D::Val>>,
    /// Processor flags, indexed by [`flag_idx`].
    flags: [Option<D::Val>; NUM_FLAGS],
    /// Lifter temporaries, indexed by temp id (dense, grows on demand).
    temps: Vec<Option<D::Val>>,
    /// Vector/segment/unknown registers that aren't a modelled GPR — keyed by
    /// (lowercased) name. The slow path; rare in arithmetic-heavy code.
    other: HashMap<String, D::Val>,
    /// Which ISA's register layout to apply.
    arch: RegArch,
}

impl<D: Domain> Default for RegFile<D> {
    fn default() -> Self {
        Self::with_arch(RegArch::X86_64)
    }
}

// `Domain::Val: Clone` always holds, so a register file is cloneable regardless
// of the domain (used to fork symbolic states).
impl<D: Domain> Clone for RegFile<D> {
    fn clone(&self) -> Self {
        Self {
            cells: self.cells.clone(),
            flags: self.flags.clone(),
            temps: self.temps.clone(),
            other: self.other.clone(),
            arch: self.arch,
        }
    }
}

impl<D: Domain> RegFile<D> {
    pub fn new() -> Self {
        Self::default()
    }

    /// A register file for a specific ISA layout.
    pub fn with_arch(arch: RegArch) -> Self {
        Self {
            cells: (0..NUM_PARENTS).map(|_| None).collect(),
            flags: std::array::from_fn(|_| None),
            temps: Vec::new(),
            other: HashMap::new(),
            arch,
        }
    }

    /// The ISA register layout used by this file.
    pub fn arch(&self) -> RegArch {
        self.arch
    }

    /// Natural width of a register in this file's selected architecture.
    /// This is architecture-aware for ambiguous names such as `sp`.
    pub(crate) fn width(&self, reg: &VReg) -> Option<Width> {
        match reg {
            VReg::Flag(_) => Some(Width::W1),
            VReg::Temp(_) => None,
            VReg::Phys(name) => {
                let name = lower(name);
                if self.arch == RegArch::AArch64 && is_aarch64_zero_reg(&name) {
                    return Some(if name.as_ref() == "wzr" {
                        Width::W32
                    } else {
                        Width::W64
                    });
                }
                self.slot(&name)
                    .map(|slot| Width(slot.width))
                    .or_else(|| reg.width())
            }
        }
    }

    /// Resolve a physical register name to its canonical slot for this arch.
    fn slot(&self, name: &str) -> Option<RegSlot> {
        match self.arch {
            RegArch::X86_64 => X86_64_SLOTS.get(name).copied(),
            RegArch::AArch64 => AARCH64_SLOTS.get(name).copied(),
        }
    }

    /// The canonical full-width cell value for parent index `parent`, zero if
    /// unset.
    fn cell(&mut self, dom: &mut D, parent: u8) -> D::Val {
        if let Some(v) = &self.cells[parent as usize] {
            v.clone()
        } else {
            dom.constant(Width::W64, 0)
        }
    }

    /// Read a register at its natural width.
    pub fn read(&mut self, dom: &mut D, reg: &VReg) -> D::Val {
        match reg {
            VReg::Flag(f) => self.flags[flag_idx(*f)]
                .clone()
                .unwrap_or_else(|| dom.constant(Width::W1, 0)),
            VReg::Temp(id) => self
                .temps
                .get(*id as usize)
                .and_then(|o| o.clone())
                .unwrap_or_else(|| dom.constant(Width::W64, 0)),
            VReg::Phys(name) => {
                let n = lower(name);
                // AArch64 zero register always reads 0.
                if self.arch == RegArch::AArch64 && is_aarch64_zero_reg(&n) {
                    let w = if n.as_ref() == "wzr" {
                        Width::W32
                    } else {
                        Width::W64
                    };
                    return dom.constant(w, 0);
                }
                match self.slot(&n) {
                    Some(slot) => {
                        let parent = self.cell(dom, slot.parent);
                        if slot.offset == 0 && slot.width == 64 {
                            parent
                        } else {
                            dom.extract(&parent, slot.offset + slot.width, slot.offset)
                        }
                    }
                    // Non-GPR (vector/segment/unknown): its own full-width cell.
                    None => self
                        .other
                        .get(n.as_ref())
                        .cloned()
                        .unwrap_or_else(|| dom.constant(Width::W64, 0)),
                }
            }
        }
    }

    /// Write `val` (already at `reg`'s natural width) into `reg`, applying
    /// x86-64 partial-register semantics.
    pub fn write(&mut self, dom: &mut D, reg: &VReg, val: D::Val) {
        match reg {
            VReg::Flag(f) => self.flags[flag_idx(*f)] = Some(val),
            VReg::Temp(id) => {
                let id = *id as usize;
                if id >= self.temps.len() {
                    self.temps.resize_with(id + 1, || None);
                }
                self.temps[id] = Some(val);
            }
            VReg::Phys(name) => {
                let n = lower(name);
                // AArch64 zero register discards writes.
                if self.arch == RegArch::AArch64 && is_aarch64_zero_reg(&n) {
                    return;
                }
                match self.slot(&n) {
                    Some(slot) => {
                        let new = self.merge_subreg(dom, &slot, val);
                        self.cells[slot.parent as usize] = Some(new);
                    }
                    None => {
                        self.other.insert(n.into_owned(), val);
                    }
                }
            }
        }
    }

    /// Compute the new full-width parent value when writing `val` into `slot`.
    fn merge_subreg(&mut self, dom: &mut D, slot: &RegSlot, val: D::Val) -> D::Val {
        match (slot.offset, slot.width) {
            // Full write.
            (0, 64) => val,
            // 32-bit write zero-extends into the 64-bit parent.
            (0, 32) => dom.zext(&val, Width::W32, Width::W64),
            // Low sub-register write preserves the high bits of the parent:
            //   parent' = concat(high_part, val)
            (0, w) => {
                let parent = self.cell(dom, slot.parent);
                let high = dom.extract(&parent, 64, w); // bits [w:64)
                dom.concat(&high, &val, Width(64 - w), Width(w))
            }
            // High-byte write (ah/bh/ch/dh): bits [8:16) change, rest preserved.
            (8, 8) => {
                let parent = self.cell(dom, slot.parent);
                let low = dom.extract(&parent, 8, 0); // [0:8)
                let high = dom.extract(&parent, 64, 16); // [16:64)
                                                         // reassemble: high(48) : val(8) : low(8)
                let mid = dom.concat(&val, &low, Width::W8, Width::W8); // [0:16)
                dom.concat(&high, &mid, Width(48), Width::W16)
            }
            // No other offset/width combinations occur in the x86-64 table.
            (off, w) => {
                let parent = self.cell(dom, slot.parent);
                let below = dom.extract(&parent, off, 0);
                let above_lo = off + w;
                let above = dom.extract(&parent, 64, above_lo);
                let lower = dom.concat(&val, &below, Width(w), Width(off));
                dom.concat(&above, &lower, Width(64 - above_lo), Width(above_lo))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::concrete::Concrete;
    use crate::ir::types::VReg;

    fn rf() -> (Concrete, RegFile<Concrete>) {
        (Concrete, RegFile::new())
    }

    #[test]
    fn full_register_round_trips() {
        let (mut d, mut r) = rf();
        let v = d.constant(Width::W64, 0xdead_beef_cafe_babe);
        r.write(&mut d, &VReg::phys("rax"), v);
        assert_eq!(r.read(&mut d, &VReg::phys("rax")), 0xdead_beef_cafe_babe);
    }

    #[test]
    fn write_eax_zeroes_upper_rax() {
        let (mut d, mut r) = rf();
        let full = d.constant(Width::W64, 0xffff_ffff_ffff_ffff);
        r.write(&mut d, &VReg::phys("rax"), full);
        // Writing eax must clear the top 32 bits (x86-64 rule).
        let eax_val = d.constant(Width::W32, 0x1234_5678);
        r.write(&mut d, &VReg::phys("eax"), eax_val);
        assert_eq!(r.read(&mut d, &VReg::phys("rax")), 0x1234_5678);
        assert_eq!(r.read(&mut d, &VReg::phys("eax")), 0x1234_5678);
    }

    #[test]
    fn aarch64_sp_width_is_not_the_x86_word_alias() {
        let regs: RegFile<Concrete> = RegFile::with_arch(RegArch::AArch64);
        assert_eq!(regs.width(&VReg::phys("sp")), Some(Width::W64));
        assert_eq!(regs.width(&VReg::phys("wsp")), Some(Width::W32));
    }

    #[test]
    fn write_ax_preserves_upper_bits() {
        let (mut d, mut r) = rf();
        let full = d.constant(Width::W64, 0xffff_ffff_ffff_ffff);
        r.write(&mut d, &VReg::phys("rax"), full);
        let ax_val = d.constant(Width::W16, 0xbeef);
        r.write(&mut d, &VReg::phys("ax"), ax_val);
        // Only the low 16 bits change; the rest of rax is preserved.
        assert_eq!(r.read(&mut d, &VReg::phys("rax")), 0xffff_ffff_ffff_beef);
        assert_eq!(r.read(&mut d, &VReg::phys("ax")), 0xbeef);
    }

    #[test]
    fn write_al_preserves_rest() {
        let (mut d, mut r) = rf();
        let full = d.constant(Width::W64, 0xffff_ffff_ffff_ffff);
        r.write(&mut d, &VReg::phys("rax"), full);
        let al_val = d.constant(Width::W8, 0x42);
        r.write(&mut d, &VReg::phys("al"), al_val);
        assert_eq!(r.read(&mut d, &VReg::phys("rax")), 0xffff_ffff_ffff_ff42);
        assert_eq!(r.read(&mut d, &VReg::phys("al")), 0x42);
    }

    #[test]
    fn high_byte_register_addresses_bits_8_to_16() {
        let (mut d, mut r) = rf();
        let full = d.constant(Width::W64, 0x0000_0000_0000_0000);
        r.write(&mut d, &VReg::phys("rax"), full);
        let ah_val = d.constant(Width::W8, 0x7e);
        r.write(&mut d, &VReg::phys("ah"), ah_val);
        // ah occupies bits [8:16).
        assert_eq!(r.read(&mut d, &VReg::phys("rax")), 0x7e00);
        assert_eq!(r.read(&mut d, &VReg::phys("ah")), 0x7e);
        assert_eq!(r.read(&mut d, &VReg::phys("al")), 0x00);
    }

    #[test]
    fn distinct_registers_are_independent() {
        let (mut d, mut r) = rf();
        let a = d.constant(Width::W64, 0x1111);
        let b = d.constant(Width::W64, 0x2222);
        r.write(&mut d, &VReg::phys("rax"), a);
        r.write(&mut d, &VReg::phys("rbx"), b);
        assert_eq!(r.read(&mut d, &VReg::phys("rax")), 0x1111);
        assert_eq!(r.read(&mut d, &VReg::phys("rbx")), 0x2222);
    }

    #[test]
    fn r8d_zeroes_upper_r8() {
        let (mut d, mut r) = rf();
        let full = d.constant(Width::W64, 0xffff_ffff_ffff_ffff);
        r.write(&mut d, &VReg::phys("r8"), full);
        let v = d.constant(Width::W32, 0xabcd);
        r.write(&mut d, &VReg::phys("r8d"), v);
        assert_eq!(r.read(&mut d, &VReg::phys("r8")), 0xabcd);
    }

    #[test]
    fn flags_and_temps_store_independently() {
        let (mut d, mut r) = rf();
        let one = d.constant(Width::W1, 1);
        r.write(&mut d, &VReg::Flag(Flag::Z), one);
        assert_eq!(r.read(&mut d, &VReg::Flag(Flag::Z)), 1);
        assert_eq!(r.read(&mut d, &VReg::Flag(Flag::C)), 0); // unset → 0

        let t = d.constant(Width::W64, 0x99);
        r.write(&mut d, &VReg::Temp(3), t);
        assert_eq!(r.read(&mut d, &VReg::Temp(3)), 0x99);
        assert_eq!(r.read(&mut d, &VReg::Temp(7)), 0); // unset → 0
    }

    #[test]
    fn unset_register_reads_zero() {
        let (mut d, mut r) = rf();
        assert_eq!(r.read(&mut d, &VReg::phys("rcx")), 0);
    }

    // ---- AArch64 layout ----

    fn rf_arm() -> (Concrete, RegFile<Concrete>) {
        (Concrete, RegFile::with_arch(RegArch::AArch64))
    }

    #[test]
    fn arm64_w_register_is_low_half_and_zero_extends() {
        let (mut d, mut r) = rf_arm();
        let full = d.constant(Width::W64, 0xffff_ffff_ffff_ffff);
        r.write(&mut d, &VReg::phys("x0"), full);
        // Writing w0 zeroes the upper 32 bits of x0 (AArch64 rule, like x86-64).
        let w0 = d.constant(Width::W32, 0x1234_5678);
        r.write(&mut d, &VReg::phys("w0"), w0);
        assert_eq!(r.read(&mut d, &VReg::phys("x0")), 0x1234_5678);
        assert_eq!(r.read(&mut d, &VReg::phys("w0")), 0x1234_5678);
    }

    #[test]
    fn arm64_lr_aliases_x30_and_sp_is_64bit() {
        let (mut d, mut r) = rf_arm();
        let v = d.constant(Width::W64, 0xabcd);
        r.write(&mut d, &VReg::phys("lr"), v);
        assert_eq!(r.read(&mut d, &VReg::phys("x30")), 0xabcd, "lr aliases x30");
        let sp = d.constant(Width::W64, 0x7fff_0000);
        r.write(&mut d, &VReg::phys("sp"), sp);
        assert_eq!(r.read(&mut d, &VReg::phys("sp")), 0x7fff_0000);
    }

    #[test]
    fn arm64_zero_register_reads_zero_and_discards_writes() {
        let (mut d, mut r) = rf_arm();
        let v = d.constant(Width::W64, 0xdead);
        r.write(&mut d, &VReg::phys("xzr"), v); // discarded
        assert_eq!(r.read(&mut d, &VReg::phys("xzr")), 0);
        assert_eq!(r.read(&mut d, &VReg::phys("wzr")), 0);
    }

    #[test]
    fn arm64_and_x86_layouts_are_independent() {
        // `sp` means 16-bit (x86) in one file and 64-bit in the other.
        let (mut dx, mut rx) = rf();
        let (mut da, mut ra) = rf_arm();
        let big = dx.constant(Width::W64, 0xffff_ffff);
        rx.write(&mut dx, &VReg::phys("sp"), big); // x86: writes 16-bit sp
        assert_eq!(rx.read(&mut dx, &VReg::phys("sp")), 0xffff); // 16-bit view
        let v = da.constant(Width::W64, 0xffff_ffff);
        ra.write(&mut da, &VReg::phys("sp"), v); // arm64: 64-bit sp
        assert_eq!(ra.read(&mut da, &VReg::phys("sp")), 0xffff_ffff);
    }
}
