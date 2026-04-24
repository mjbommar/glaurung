//! LLIR type definitions — see crate::ir for design notes.

use std::fmt;

/// Status-like flags modelled as virtual registers. These are *condition-code
/// values*, not the literal x86 EFLAGS bits — keeping them in terms of
/// machine-independent comparison results lets other backends (ARM `NZCV`,
/// RISC-V branches) map cleanly onto the same IR.
///
/// * `Z`   — equal / zero (result == 0)
/// * `C`   — carry / unsigned-less-than (a `ult` b)
/// * `S`   — raw sign — top bit of the last arithmetic/logic result; equals
///           the x86 `SF` flag. After `test` this differs from [`Flag::Slt`]
///           (which is `SF ^ OF` and would be wrong for test-derived paths).
/// * `Slt` — signed-less-than (a `slt` b; x86 `SF ^ OF` after cmp)
/// * `Sle` — signed-less-or-equal (a `sle` b; `Z || Slt`)
/// * `O`   — overflow
/// * `P`   — parity
/// * `A`   — auxiliary carry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Flag {
    Z,
    C,
    S,
    Slt,
    Sle,
    O,
    P,
    A,
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
}

impl MemOp {
    /// Construct a MemOp with no segment override (the common case).
    pub fn plain(base: Option<VReg>, index: Option<VReg>, scale: u8, disp: i64, size: u8) -> Self {
        Self {
            base,
            index,
            scale,
            disp,
            size,
            segment: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Sar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnOp {
    Not,
    Neg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    /// Unsigned less-than.
    Ult,
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
    CondJump {
        cond: VReg,
        target: u64,
    },
    Call {
        target: CallTarget,
    },
    Return,
    Nop,
    /// Could not lift faithfully. The mnemonic is preserved so analysers can
    /// flag unsupported instructions rather than silently miscompile.
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
                Flag::S => write!(f, "%sf"),
                Flag::Slt => write!(f, "%slt"),
                Flag::Sle => write!(f, "%sle"),
                Flag::O => write!(f, "%of"),
                Flag::P => write!(f, "%pf"),
                Flag::A => write!(f, "%af"),
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

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Op::Assign { dst, src } => write!(f, "{} = {}", dst, src),
            Op::Bin {
                dst,
                op,
                lhs,
                rhs,
            } => write!(f, "{} = {:?} {} {}", dst, op, lhs, rhs),
            Op::Un { dst, op, src } => write!(f, "{} = {:?} {}", dst, op, src),
            Op::Cmp {
                dst,
                op,
                lhs,
                rhs,
            } => write!(f, "{} = cmp {:?} {} {}", dst, op, lhs, rhs),
            Op::Load { dst, addr } => write!(f, "{} = load[{} bytes] {:?}", dst, addr.size, addr),
            Op::Store { addr, src } => write!(f, "store[{} bytes] {:?} <- {}", addr.size, addr, src),
            Op::Jump { target } => write!(f, "jmp 0x{:x}", target),
            Op::CondJump { cond, target } => write!(f, "if {} jmp 0x{:x}", cond, target),
            Op::Call { target } => match target {
                CallTarget::Direct(a) => write!(f, "call 0x{:x}", a),
                CallTarget::Indirect(v) => write!(f, "call {}", v),
            },
            Op::Return => write!(f, "ret"),
            Op::Nop => write!(f, "nop"),
            Op::Unknown { mnemonic } => write!(f, "unk({})", mnemonic),
        }
    }
}
