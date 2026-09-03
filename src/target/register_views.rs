//! ARM32 register-storage views owned by the canonical target boundary.
//!
//! Core aliases such as `a1` and `r0` name one 32-bit storage location. The
//! scalar VFP/NEON bank is different: `s0` and `s1` are the low and high
//! halves of `d0`, while `d0` and `d1` are the low and high halves of `q0`.
//! A consumer that sees only an `s0` or `d0` write must therefore treat `q0`
//! as partially defined rather than as untouched or completely replaced.

use super::TargetId;

const CORE: &[&str] = &[
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr",
    "pc",
];

const DOUBLE: &[&str] = &[
    "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "d10", "d11", "d12", "d13", "d14",
    "d15", "d16", "d17", "d18", "d19", "d20", "d21", "d22", "d23", "d24", "d25", "d26", "d27",
    "d28", "d29", "d30", "d31",
];

const QUAD: &[&str] = &[
    "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7", "q8", "q9", "q10", "q11", "q12", "q13", "q14",
    "q15",
];

/// Non-aliasing architectural register bank.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegisterBank {
    /// ARM core integer registers.
    Core,
    /// ARM scalar VFP registers.
    Vfp,
}

/// One architectural spelling's bit window onto a canonical storage parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RegisterView {
    name: &'static str,
    parent: &'static str,
    offset: u16,
    width: u16,
    parent_width: u16,
    bank: RegisterBank,
}

impl RegisterView {
    /// Canonical spelling of the queried view.
    pub fn name(self) -> &'static str {
        self.name
    }

    /// Canonical storage parent shared by overlapping views.
    pub fn parent(self) -> &'static str {
        self.parent
    }

    /// Least-significant bit of this view in its parent.
    pub fn offset(self) -> u16 {
        self.offset
    }

    /// Width of this view in bits.
    pub fn width(self) -> u16 {
        self.width
    }

    /// Width of the canonical parent in bits.
    pub fn parent_width(self) -> u16 {
        self.parent_width
    }

    /// Architectural storage bank.
    pub fn bank(self) -> RegisterBank {
        self.bank
    }

    /// Whether writing this view replaces every bit of its parent.
    pub fn is_complete_write(self) -> bool {
        self.offset == 0 && self.width == self.parent_width
    }
}

fn core_index(name: &str) -> Option<usize> {
    let alias = match name {
        "a1" => 0,
        "a2" => 1,
        "a3" => 2,
        "a4" => 3,
        "v1" => 4,
        "v2" => 5,
        "v3" => 6,
        "v4" => 7,
        "v5" => 8,
        "v6" | "sb" => 9,
        "v7" | "sl" => 10,
        "v8" | "fp" => 11,
        "ip" => 12,
        "r13" | "sp" => 13,
        "r14" | "lr" => 14,
        "r15" | "pc" => 15,
        _ => {
            return name
                .strip_prefix('r')?
                .parse::<usize>()
                .ok()
                .filter(|i| *i <= 12)
        }
    };
    Some(alias)
}

fn numbered(name: &str, prefix: char, limit: usize) -> Option<usize> {
    name.strip_prefix(prefix)?
        .parse::<usize>()
        .ok()
        .filter(|index| *index < limit)
}

/// Query one register view. Unsupported targets and unknown spellings return
/// `None`; a caller must not borrow a similarly named view from another ISA.
pub(super) fn view(target: TargetId, name: &str) -> Option<RegisterView> {
    if target != TargetId::Arm32 {
        return None;
    }
    if let Some(index) = core_index(name) {
        return Some(RegisterView {
            name: CORE[index],
            parent: CORE[index],
            offset: 0,
            width: 32,
            parent_width: 32,
            bank: RegisterBank::Core,
        });
    }
    if let Some(index) = numbered(name, 's', 32) {
        return Some(RegisterView {
            name: name_for_single(index),
            parent: QUAD[index / 4],
            offset: (index % 4) as u16 * 32,
            width: 32,
            parent_width: 128,
            bank: RegisterBank::Vfp,
        });
    }
    if let Some(index) = numbered(name, 'd', DOUBLE.len()) {
        return Some(RegisterView {
            name: DOUBLE[index],
            parent: QUAD[index / 2],
            offset: (index % 2) as u16 * 64,
            width: 64,
            parent_width: 128,
            bank: RegisterBank::Vfp,
        });
    }
    numbered(name, 'q', QUAD.len()).map(|index| RegisterView {
        name: QUAD[index],
        parent: QUAD[index],
        offset: 0,
        width: 128,
        parent_width: 128,
        bank: RegisterBank::Vfp,
    })
}

fn name_for_single(index: usize) -> &'static str {
    const SINGLE: &[&str] = &[
        "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "s12", "s13",
        "s14", "s15", "s16", "s17", "s18", "s19", "s20", "s21", "s22", "s23", "s24", "s25", "s26",
        "s27", "s28", "s29", "s30", "s31",
    ];
    SINGLE[index]
}
