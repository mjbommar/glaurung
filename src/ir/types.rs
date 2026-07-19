//! LLIR type definitions — see crate::ir for design notes.

use std::fmt;

/// Bit width of a value or operation. Newtype over a `u16` count of **bits** so
/// the type system distinguishes widths from arbitrary integers and so callers
/// read at an explicit, machine-checkable width. See
/// `docs/design/execution-engine/02-architecture/executable-llir.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Width(pub u16);

impl Width {
    pub const W1: Width = Width(1);
    pub const W8: Width = Width(8);
    pub const W16: Width = Width(16);
    pub const W32: Width = Width(32);
    pub const W64: Width = Width(64);
    pub const W128: Width = Width(128);
    pub const W256: Width = Width(256);
    pub const W512: Width = Width(512);

    /// Width in bits.
    pub fn bits(self) -> u16 {
        self.0
    }
    /// Width in bytes (truncating; sub-byte widths report 0).
    pub fn bytes(self) -> u16 {
        self.0 / 8
    }
    /// Construct from a byte count (e.g. `MemOp.size`).
    pub fn from_bytes(bytes: u16) -> Width {
        Width(bytes.saturating_mul(8))
    }
}

impl fmt::Display for Width {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "i{}", self.0)
    }
}

/// Byte order of a memory access. The IR carries endianness explicitly so the
/// execution engine stays endian-agnostic — the lifter decides per access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Endian {
    #[default]
    Little,
    Big,
}

/// Status-like flags modelled as virtual registers. These are *condition-code
/// values*, not the literal x86 EFLAGS bits — keeping them in terms of
/// machine-independent comparison results lets other backends (ARM `NZCV`,
/// RISC-V branches) map cleanly onto the same IR.
///
/// * `Z`   — equal / zero (result == 0)
/// * `C`   — carry / unsigned-less-than (a `ult` b)
/// * `Ule` — unsigned-less-or-equal (a `ule` b; `C || Z`)
/// * `S`   — raw sign — top bit of the last arithmetic/logic result; equals
///           the x86 `SF` flag. After `test` this differs from [`Flag::Slt`]
///           (which is `SF ^ OF` and would be wrong for test-derived paths).
/// * `Slt` — signed-less-than (a `slt` b; x86 `SF ^ OF` after cmp)
/// * `Sle` — signed-less-or-equal (a `sle` b; `Z || Slt`)
/// * `O`   — overflow
/// * `P`   — parity
/// * `A`   — auxiliary carry
/// * `Bit` — internal one-bit predicate for flag-preserving ISA branches such
///           as AArch64 `tbz`/`tbnz`; it is not an architectural status flag
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Flag {
    Z,
    C,
    Ule,
    S,
    Slt,
    Sle,
    O,
    P,
    A,
    Bit,
}

/// A virtual register. Named physical registers carry the source-ISA name
/// verbatim (`"rax"`, `"x0"`) so downstream annotations can round-trip.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VReg {
    /// Physical / ISA register, e.g. `"rax"`, `"rdi"`, `"x0"`.
    Phys(String),
    /// Synthetic temporary introduced during lifting.
    Temp(u32),
    /// Processor status flag.
    Flag(Flag),
}

/// A readable RHS value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Reg(VReg),
    /// Integer constant. We store as i64 (signed) because most x86 immediates
    /// are sign-extended to register width.
    Const(i64),
    /// Absolute VA (e.g. for lifted RIP-relative `lea`s that resolve to a
    /// concrete VA at lift time).
    Addr(u64),
}

/// Effective address of a memory operand.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemOp {
    pub base: Option<VReg>,
    pub index: Option<VReg>,
    pub scale: u8, // 1, 2, 4, 8
    pub disp: i64,
    /// Access width in bytes (1, 2, 4, 8).
    pub size: u8,
    /// Segment override: `Some("fs")` / `Some("gs")` for x86-64 TLS; None
    /// for ARM64 and for x86 accesses that use a default segment (ds/ss/cs).
    pub segment: Option<String>,
    /// Byte order of the access. Defaults to little-endian (x86/ARM common case);
    /// the lifter overrides for big-endian targets.
    pub endian: Endian,
}

impl MemOp {
    /// Construct a MemOp with no segment override (the common case),
    /// little-endian.
    pub fn plain(base: Option<VReg>, index: Option<VReg>, scale: u8, disp: i64, size: u8) -> Self {
        Self {
            base,
            index,
            scale,
            disp,
            size,
            segment: None,
            endian: Endian::Little,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Sar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnOp {
    Not,
    Neg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CmpOp {
    Eq,
    Ne,
    /// Unsigned less-than.
    Ult,
    /// Unsigned less-or-equal.
    Ule,
    /// Signed less-than.
    Slt,
    /// Signed less-or-equal.
    Sle,
}

/// How a call transfers control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallTarget {
    Direct(u64),
    Indirect(Value),
}

/// A single LLIR operation. Multiple LLIR ops may correspond to one machine
/// instruction (e.g. `push rax` expands to a `sub rsp, 8` + `store [rsp], rax`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Assign {
        dst: VReg,
        src: Value,
    },
    /// Conditional register assignment. `dst` receives `src` when `cond` is
    /// true; otherwise its previous value is preserved.
    CondAssign {
        dst: VReg,
        cond: VReg,
        src: Value,
    },
    Bin {
        dst: VReg,
        op: BinOp,
        lhs: Value,
        rhs: Value,
    },
    Un {
        dst: VReg,
        op: UnOp,
        src: Value,
    },
    /// Write a boolean comparison result into a flag / temp.
    Cmp {
        dst: VReg,
        op: CmpOp,
        lhs: Value,
        rhs: Value,
    },
    Load {
        dst: VReg,
        addr: MemOp,
    },
    Store {
        addr: MemOp,
        src: Value,
    },
    /// Unconditional direct jump.
    Jump {
        target: u64,
    },
    /// Conditional jump on a previously-computed flag/bool value.
    /// `inverted = true` means "take the jump when `cond` is *not* set" —
    /// this is how JNE / JAE / JGE / etc. lift while still letting their
    /// positive sibling (JE / JB / JL) share the same flag VReg as the
    /// `cmp` that produced it. Downstream passes use this to render
    /// `if (X != Y)` vs `if (X == Y)` correctly when hoisting the Cmp.
    CondJump {
        cond: VReg,
        target: u64,
        inverted: bool,
    },
    Call {
        target: CallTarget,
    },
    Return,
    Nop,
    /// Zero-extend `src` (`from` bits) into `dst` (`to` bits, `to >= from`).
    /// Mirrors P-code `INT_ZEXT` / BIL `UNSIGNED`.
    ZExt {
        dst: VReg,
        src: Value,
        from: Width,
        to: Width,
    },
    /// Sign-extend `src` (`from` bits) into `dst` (`to` bits, `to >= from`).
    /// Mirrors P-code `INT_SEXT` / BIL `SIGNED`.
    SExt {
        dst: VReg,
        src: Value,
        from: Width,
        to: Width,
    },
    /// Truncate `src` (`from` bits) to its low `to` bits (`to <= from`).
    /// Mirrors P-code `SUBPIECE`(0) / BIL `LOW`.
    Trunc {
        dst: VReg,
        src: Value,
        from: Width,
        to: Width,
    },
    /// Extract bits `[lo, hi)` of `src` into `dst` (a bit slice; `hi > lo`).
    /// Mirrors Miasm `ExprSlice` / sub-register reads.
    Extract {
        dst: VReg,
        src: Value,
        hi: u16,
        lo: u16,
    },
    /// Concatenate: `dst = (hi << width(lo)) | lo`, most-significant part first.
    /// Mirrors P-code `PIECE` / Miasm `ExprCompose`.
    Concat {
        dst: VReg,
        hi: Value,
        lo: Value,
    },
    /// Pure select: `dst = cond ? t : e`, where `cond` is a 1-bit value. Unlike
    /// [`Op::CondAssign`] (which preserves the old value when false), `Ite`
    /// always writes and is merge-friendly for symbolic execution.
    Ite {
        dst: VReg,
        cond: VReg,
        t: Value,
        e: Value,
        width: Width,
    },
    /// A typed, side-effect-declaring opaque operation — the executable-IR
    /// replacement for [`Op::Unknown`]. Models VEX "dirty calls" / P-code
    /// `CALLOTHER` / Binary Ninja intrinsics: an opaque body with explicit
    /// inputs, typed outputs, and a declared memory footprint, so dataflow and
    /// symbolic execution stay sound even when the semantics are not modelled.
    /// Refinable into real ops later without changing the IR shape.
    Intrinsic {
        /// Operation name, e.g. `"cpuid"`, `"rdtsc"`, `"pshufb"`, `"syscall"`.
        name: String,
        /// Input operands read by the operation.
        ins: Vec<Value>,
        /// Output registers written, with their widths.
        outs: Vec<(VReg, Width)>,
        /// Whether the operation reads memory (conservatively `true` if unknown).
        reads_mem: bool,
        /// Whether the operation writes memory (conservatively `true` if unknown).
        writes_mem: bool,
    },
    /// Could not lift faithfully. The mnemonic is preserved so analysers can
    /// flag unsupported instructions rather than silently miscompile.
    ///
    /// **Deprecated** in favour of [`Op::Intrinsic`], which additionally declares
    /// the operation's read/write footprint so execution stays sound. Retained
    /// during the lifter migration (Phase 0 task 0.7); new lifting code should
    /// emit `Intrinsic`.
    Unknown {
        mnemonic: String,
    },
}

/// A single LLIR instruction annotated with its source VA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlirInstr {
    /// VA of the *machine* instruction this op came from. Multiple LLIR
    /// instructions may share one `va` when one machine instruction expanded
    /// into several LLIR ops.
    pub va: u64,
    pub op: Op,
}

/// A straight-line LLIR basic block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LlirBlock {
    pub start_va: u64,
    /// Exclusive upper bound of the last machine instruction contained.
    pub end_va: u64,
    pub instrs: Vec<LlirInstr>,
    /// Successor VAs (unconditional or conditional targets + fallthrough).
    pub succs: Vec<u64>,
}

/// An LLIR function — one entry VA and a list of blocks. No SSA, no dominator
/// tree yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlirFunction {
    pub entry_va: u64,
    pub blocks: Vec<LlirBlock>,
}

// --- Convenience constructors & helpers --------------------------------------

impl VReg {
    pub fn phys(name: impl Into<String>) -> Self {
        Self::Phys(name.into())
    }

    /// Bit width of this register where derivable.
    ///
    /// * `Flag` is always 1 bit.
    /// * `Phys` is looked up by ISA register name (x86-64 + AArch64).
    /// * `Temp` width is not encoded in the name; it is tracked by the producing
    ///   op / executor, so this returns `None` for temporaries.
    pub fn width(&self) -> Option<Width> {
        match self {
            VReg::Flag(_) => Some(Width::W1),
            VReg::Temp(_) => None,
            VReg::Phys(name) => phys_reg_width(name),
        }
    }
}

/// Bit width of a physical ISA register by name (x86-64 and AArch64). Returns
/// `None` for names we don't model (callers treat that as "unknown width").
///
/// This helper is **arch-agnostic** and resolves purely by name, so a few short
/// names that collide across ISAs (notably `sp`/`bp` — x86 16-bit registers vs
/// AArch64's 64-bit stack/frame pointer) resolve to their **x86** width here.
/// The authoritative, arch-aware width comes from the per-arch register layout
/// introduced with the execution engine's `CpuModel` (Phase 1); until then
/// callers that know the architecture should prefer that.
pub fn phys_reg_width(name: &str) -> Option<Width> {
    let n = name.to_ascii_lowercase();
    // x86-64 64-bit GPRs
    const R64: &[&str] = &[
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15", "rip",
    ];
    // x86-64 32-bit GPRs
    const R32: &[&str] = &[
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "r8d", "r9d", "r10d", "r11d",
        "r12d", "r13d", "r14d", "r15d", "eip",
    ];
    // x86-64 16-bit GPRs
    const R16: &[&str] = &[
        "ax", "bx", "cx", "dx", "si", "di", "bp", "sp", "r8w", "r9w", "r10w", "r11w", "r12w",
        "r13w", "r14w", "r15w",
    ];
    // x86-64 8-bit GPRs (low and high byte)
    const R8: &[&str] = &[
        "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh", "sil", "dil", "bpl", "spl", "r8b", "r9b",
        "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
    ];
    if R64.contains(&n.as_str()) {
        return Some(Width::W64);
    }
    if R32.contains(&n.as_str()) {
        return Some(Width::W32);
    }
    if R16.contains(&n.as_str()) {
        return Some(Width::W16);
    }
    if R8.contains(&n.as_str()) {
        return Some(Width::W8);
    }
    // x86 segment registers
    if matches!(n.as_str(), "cs" | "ds" | "es" | "fs" | "gs" | "ss") {
        return Some(Width::W16);
    }
    // x86 SSE/AVX vector registers
    if let Some(rest) = n.strip_prefix("xmm") {
        if rest.parse::<u8>().is_ok() {
            return Some(Width::W128);
        }
    }
    if let Some(rest) = n.strip_prefix("ymm") {
        if rest.parse::<u8>().is_ok() {
            return Some(Width::W256);
        }
    }
    if let Some(rest) = n.strip_prefix("zmm") {
        if rest.parse::<u8>().is_ok() {
            return Some(Width::W512);
        }
    }
    // AArch64 64-bit GPRs: x0..x30, plus sp/xzr/pc
    if let Some(rest) = n.strip_prefix('x') {
        if let Ok(idx) = rest.parse::<u8>() {
            if idx <= 30 {
                return Some(Width::W64);
            }
        }
    }
    if matches!(n.as_str(), "sp" | "xzr" | "pc" | "lr" | "fp") {
        return Some(Width::W64);
    }
    // AArch64 32-bit views: w0..w30, wzr
    if let Some(rest) = n.strip_prefix('w') {
        if let Ok(idx) = rest.parse::<u8>() {
            if idx <= 30 {
                return Some(Width::W32);
            }
        }
    }
    if n == "wzr" {
        return Some(Width::W32);
    }
    // AArch64 SIMD/FP: v0..v31 (128b), q (128), d (64), s (32), h (16), b (8)
    for (pfx, w) in [
        ('v', Width::W128),
        ('q', Width::W128),
        ('d', Width::W64),
        ('s', Width::W32),
        ('h', Width::W16),
    ] {
        if let Some(rest) = n.strip_prefix(pfx) {
            if let Ok(idx) = rest.parse::<u8>() {
                if idx <= 31 {
                    return Some(w);
                }
            }
        }
    }
    None
}

impl Value {
    pub fn reg(name: impl Into<String>) -> Self {
        Value::Reg(VReg::phys(name))
    }
    pub fn konst(v: i64) -> Self {
        Value::Const(v)
    }
}

impl fmt::Display for VReg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VReg::Phys(n) => write!(f, "%{}", n),
            VReg::Temp(i) => write!(f, "%t{}", i),
            VReg::Flag(fl) => match fl {
                Flag::Z => write!(f, "%zf"),
                Flag::C => write!(f, "%cf"),
                Flag::Ule => write!(f, "%ule"),
                Flag::S => write!(f, "%sf"),
                Flag::Slt => write!(f, "%slt"),
                Flag::Sle => write!(f, "%sle"),
                Flag::O => write!(f, "%of"),
                Flag::P => write!(f, "%pf"),
                Flag::A => write!(f, "%af"),
                Flag::Bit => write!(f, "%bitpred"),
            },
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Reg(r) => write!(f, "{}", r),
            Value::Const(v) => write!(f, "{}", v),
            Value::Addr(v) => write!(f, "@0x{:x}", v),
        }
    }
}

impl Op {
    /// Build a maximally-conservative opaque [`Op::Intrinsic`] from an
    /// unmodelled instruction mnemonic: no typed inputs/outputs, and assumed to
    /// both read and write memory. This is the lowering target for the
    /// deprecated [`Op::Unknown`] (Phase 0 task 0.7) — sound (over-approximate)
    /// but imprecise. A concrete executor halts on it; a symbolic executor
    /// havocs memory.
    pub fn opaque(mnemonic: impl Into<String>) -> Op {
        Op::Intrinsic {
            name: mnemonic.into(),
            ins: Vec::new(),
            outs: Vec::new(),
            reads_mem: true,
            writes_mem: true,
        }
    }
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Op::Assign { dst, src } => write!(f, "{} = {}", dst, src),
            Op::CondAssign { dst, cond, src } => {
                write!(f, "if {} {} = {}", cond, dst, src)
            }
            Op::Bin { dst, op, lhs, rhs } => write!(f, "{} = {:?} {} {}", dst, op, lhs, rhs),
            Op::Un { dst, op, src } => write!(f, "{} = {:?} {}", dst, op, src),
            Op::Cmp { dst, op, lhs, rhs } => write!(f, "{} = cmp {:?} {} {}", dst, op, lhs, rhs),
            Op::Load { dst, addr } => write!(f, "{} = load[{} bytes] {:?}", dst, addr.size, addr),
            Op::Store { addr, src } => {
                write!(f, "store[{} bytes] {:?} <- {}", addr.size, addr, src)
            }
            Op::Jump { target } => write!(f, "jmp 0x{:x}", target),
            Op::CondJump {
                cond,
                target,
                inverted,
            } => {
                let prefix = if *inverted { "!" } else { "" };
                write!(f, "if {}{} jmp 0x{:x}", prefix, cond, target)
            }
            Op::Call { target } => match target {
                CallTarget::Direct(a) => write!(f, "call 0x{:x}", a),
                CallTarget::Indirect(v) => write!(f, "call {}", v),
            },
            Op::Return => write!(f, "ret"),
            Op::Nop => write!(f, "nop"),
            Op::ZExt {
                dst, src, from, to, ..
            } => write!(f, "{} = zext.{}.{} {}", dst, from, to, src),
            Op::SExt {
                dst, src, from, to, ..
            } => write!(f, "{} = sext.{}.{} {}", dst, from, to, src),
            Op::Trunc {
                dst, src, from, to, ..
            } => write!(f, "{} = trunc.{}.{} {}", dst, from, to, src),
            Op::Extract { dst, src, hi, lo } => {
                write!(f, "{} = extract[{}:{}] {}", dst, hi, lo, src)
            }
            Op::Concat { dst, hi, lo } => write!(f, "{} = concat {}:{}", dst, hi, lo),
            Op::Ite {
                dst, cond, t, e, ..
            } => write!(f, "{} = {} ? {} : {}", dst, cond, t, e),
            Op::Intrinsic {
                name, ins, outs, ..
            } => {
                let outs_s: Vec<String> =
                    outs.iter().map(|(r, w)| format!("{}:{}", r, w)).collect();
                let ins_s: Vec<String> = ins.iter().map(|v| v.to_string()).collect();
                write!(
                    f,
                    "[{}] = intrinsic {}({})",
                    outs_s.join(", "),
                    name,
                    ins_s.join(", ")
                )
            }
            Op::Unknown { mnemonic } => write!(f, "unk({})", mnemonic),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn width_accessors() {
        assert_eq!(Width::W32.bits(), 32);
        assert_eq!(Width::W32.bytes(), 4);
        assert_eq!(Width::W1.bytes(), 0); // sub-byte
        assert_eq!(Width::from_bytes(8), Width::W64);
        assert_eq!(format!("{}", Width::W64), "i64");
    }

    #[test]
    fn endian_defaults_little() {
        assert_eq!(Endian::default(), Endian::Little);
    }

    #[test]
    fn memop_plain_is_little_endian() {
        let m = MemOp::plain(Some(VReg::phys("rsp")), None, 1, -8, 8);
        assert_eq!(m.endian, Endian::Little);
        assert_eq!(m.segment, None);
    }

    #[test]
    fn phys_reg_width_x86_gpr_aliases() {
        assert_eq!(phys_reg_width("rax"), Some(Width::W64));
        assert_eq!(phys_reg_width("eax"), Some(Width::W32));
        assert_eq!(phys_reg_width("ax"), Some(Width::W16));
        assert_eq!(phys_reg_width("al"), Some(Width::W8));
        assert_eq!(phys_reg_width("ah"), Some(Width::W8));
        assert_eq!(phys_reg_width("r8"), Some(Width::W64));
        assert_eq!(phys_reg_width("r8d"), Some(Width::W32));
        assert_eq!(phys_reg_width("r8w"), Some(Width::W16));
        assert_eq!(phys_reg_width("r8b"), Some(Width::W8));
        // case-insensitive
        assert_eq!(phys_reg_width("RAX"), Some(Width::W64));
    }

    #[test]
    fn phys_reg_width_x86_vectors() {
        assert_eq!(phys_reg_width("xmm0"), Some(Width::W128));
        assert_eq!(phys_reg_width("ymm15"), Some(Width::W256));
        assert_eq!(phys_reg_width("zmm3"), Some(Width::W512));
    }

    #[test]
    fn phys_reg_width_aarch64() {
        assert_eq!(phys_reg_width("x0"), Some(Width::W64));
        assert_eq!(phys_reg_width("x30"), Some(Width::W64));
        assert_eq!(phys_reg_width("w0"), Some(Width::W32));
        assert_eq!(phys_reg_width("v5"), Some(Width::W128));
        assert_eq!(phys_reg_width("d7"), Some(Width::W64));
        assert_eq!(phys_reg_width("s7"), Some(Width::W32));
    }

    #[test]
    fn phys_reg_width_ambiguous_names_prefer_x86() {
        // `sp`/`bp` collide (x86 16-bit vs AArch64 64-bit); the arch-agnostic
        // helper resolves them as x86. Arch-aware width (Phase 1 CpuModel)
        // overrides this for AArch64.
        assert_eq!(phys_reg_width("sp"), Some(Width::W16));
        assert_eq!(phys_reg_width("bp"), Some(Width::W16));
    }

    #[test]
    fn phys_reg_width_unknown_is_none() {
        assert_eq!(phys_reg_width("not_a_register"), None);
        assert_eq!(phys_reg_width("x99"), None); // out of range
    }

    #[test]
    fn vreg_width() {
        assert_eq!(VReg::phys("rax").width(), Some(Width::W64));
        assert_eq!(VReg::phys("eax").width(), Some(Width::W32));
        assert_eq!(VReg::Flag(Flag::Z).width(), Some(Width::W1));
        assert_eq!(VReg::Temp(0).width(), None); // temp width tracked elsewhere
    }

    #[test]
    fn new_ops_display() {
        let zx = Op::ZExt {
            dst: VReg::phys("rax"),
            src: Value::reg("eax"),
            from: Width::W32,
            to: Width::W64,
        };
        assert_eq!(format!("{}", zx), "%rax = zext.i32.i64 %eax");

        let ex = Op::Extract {
            dst: VReg::phys("ah"),
            src: Value::reg("rax"),
            hi: 16,
            lo: 8,
        };
        assert_eq!(format!("{}", ex), "%ah = extract[16:8] %rax");

        let intr = Op::Intrinsic {
            name: "cpuid".into(),
            ins: vec![Value::reg("eax")],
            outs: vec![
                (VReg::phys("eax"), Width::W32),
                (VReg::phys("edx"), Width::W32),
            ],
            reads_mem: false,
            writes_mem: false,
        };
        assert_eq!(
            format!("{}", intr),
            "[%eax:i32, %edx:i32] = intrinsic cpuid(%eax)"
        );
    }
}
