//! Node labels: the projection that turns an LLIR operation into a tuple.
//!
//! A CFR node's label is
//! `(op_kind, width_class, operand_arity, value_class, const_bucket, callee_class)`
//! and **never a name**. `VReg::Phys("rax")` cannot reach a label from here:
//! the only path from a register to a label runs through
//! [`crate::identity::cfr::widths`], which yields a width class and nothing
//! else. That is the whole projection, and the mask/keep table it implements is
//! reproduced in `docs/analysis/function-identity-cfr.md`.

use std::fmt::Write as _;

use crate::ir::types::{BinOp, CmpOp, Flag, UnOp, Width};

/// Bit-width class of a value, the only thing a register contributes to a label.
///
/// Register *names* are masked (BSim: "names of registers ... are intentionally
/// not incorporated"); the operand width is what is kept in their place. Widths
/// that are not one of the machine classes round **up** to the next class, so
/// an `Extract` of 24 bits and a 32-bit load land together rather than each
/// inventing a class of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WidthClass {
    /// A one-bit predicate: a flag, a comparison result, a branch condition.
    W1,
    W8,
    W16,
    W32,
    W64,
    W128,
    W256,
    W512,
    /// Four bytes or more, with the exact width deliberately discarded.
    ///
    /// Only produced under [`super::CfrSettings::nosize`]. This is BSim's
    /// `medium_nosize` template ("size differences for varnodes of 4+ bytes
    /// aren't incorporated into BSim features"), and it is the single switch
    /// that buys 32-to-64-bit matching.
    WGe4,
    /// No width could be derived. Counted as a diagnostic rather than guessed:
    /// a wrong width is a wrong feature, and a wrong feature is silent.
    Unknown,
}

impl WidthClass {
    /// Classify a bit width, rounding up to the next machine class.
    pub fn from_bits(bits: u16) -> Self {
        match bits {
            0 => WidthClass::Unknown,
            1 => WidthClass::W1,
            2..=8 => WidthClass::W8,
            9..=16 => WidthClass::W16,
            17..=32 => WidthClass::W32,
            33..=64 => WidthClass::W64,
            65..=128 => WidthClass::W128,
            129..=256 => WidthClass::W256,
            _ => WidthClass::W512,
        }
    }

    /// Classify an LLIR [`Width`].
    pub fn from_width(width: Width) -> Self {
        Self::from_bits(width.bits())
    }

    /// Bit width of this class, or `None` for [`WidthClass::Unknown`] and
    /// [`WidthClass::WGe4`], which name a set of widths rather than one.
    pub fn bits(self) -> Option<u16> {
        match self {
            WidthClass::W1 => Some(1),
            WidthClass::W8 => Some(8),
            WidthClass::W16 => Some(16),
            WidthClass::W32 => Some(32),
            WidthClass::W64 => Some(64),
            WidthClass::W128 => Some(128),
            WidthClass::W256 => Some(256),
            WidthClass::W512 => Some(512),
            WidthClass::WGe4 | WidthClass::Unknown => None,
        }
    }

    /// Collapse every class of four bytes or more into [`WidthClass::WGe4`].
    ///
    /// `W1`, `W8` and `W16` survive: BSim's `nosize` keeps `{1, 2, >=4}` bytes
    /// apart, and a one-bit predicate is not a byte at all.
    pub fn collapse_nosize(self) -> Self {
        match self {
            WidthClass::W32
            | WidthClass::W64
            | WidthClass::W128
            | WidthClass::W256
            | WidthClass::W512
            | WidthClass::WGe4 => WidthClass::WGe4,
            other => other,
        }
    }

    /// Stable token used in the label's byte encoding.
    pub fn token(self) -> &'static str {
        match self {
            WidthClass::W1 => "w1",
            WidthClass::W8 => "w8",
            WidthClass::W16 => "w16",
            WidthClass::W32 => "w32",
            WidthClass::W64 => "w64",
            WidthClass::W128 => "w128",
            WidthClass::W256 => "w256",
            WidthClass::W512 => "w512",
            WidthClass::WGe4 => "wge4",
            WidthClass::Unknown => "w?",
        }
    }
}

/// What kind of thing a value is, with its identity masked away.
///
/// Six classes, from `docs/research/program-measures-2026-09-02.md`. BSim seeds
/// a varnode with "constant-ness, and whether it is a global or a function
/// input"; this is that flag set widened into one enumeration so a node carries
/// exactly one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValueClass {
    /// A literal integer operand.
    Const,
    /// An address of program storage: an `Op`-level `Value::Addr`, or a
    /// constant that lands inside a mapped section.
    GlobalAddr,
    /// Derived from the stack or frame pointer. Stack *mechanics* are masked;
    /// that a value addresses the frame is kept, because locals are keyed by
    /// frame offset.
    StackAddr,
    /// A live-in SSA value: version zero, defined by the caller.
    FunctionInput,
    /// A merge point.
    Phi,
    /// Anything computed inside the function.
    Derived,
}

impl ValueClass {
    /// Stable token used in the label's byte encoding.
    pub fn token(self) -> &'static str {
        match self {
            ValueClass::Const => "const",
            ValueClass::GlobalAddr => "global",
            ValueClass::StackAddr => "stack",
            ValueClass::FunctionInput => "input",
            ValueClass::Phi => "phi",
            ValueClass::Derived => "derived",
        }
    }
}

/// Largest magnitude a constant may have and still be kept as `Small`.
///
/// SAFE masks every immediate with `|v| > 5000` to a single `IMM` token and
/// keeps the rest verbatim, on the grounds that small immediates identify
/// locals, arguments and struct fields; PalmTree draws the same line at five
/// hex digits (65536). We take SAFE's number because it is the tighter of the
/// two published anchors and because a bucket, unlike SAFE's kept literal, is
/// still a projection: nothing above this threshold survives as a value.
pub const SMALL_CONST_ABS_MAX: i64 = 5000;

/// Lowest address a constant may name and still be classed `PointerLike`.
///
/// One page. Every mainstream ABI leaves the first page unmapped so that a null
/// dereference faults, so a value below it is arithmetic, not an address.
pub const POINTER_LIKE_MIN: u64 = 0x1000;

/// Highest address a constant may name and still be classed `PointerLike`.
///
/// The top of the canonical low half of a 48-bit address space, which is where
/// every user-space mapping on x86-64 and AArch64 Linux lives. Above it a
/// 64-bit literal is a magic number (a hash seed, a float bit pattern, a
/// sign mask), not a pointer.
pub const POINTER_LIKE_MAX: u64 = 0x0000_7fff_ffff_ffff;

/// Bucketed constant value. The value itself never reaches a feature.
///
/// Masking large constants is unanimous across BSim (which excludes constant
/// values entirely), FunctionID's full hash, SAFE, PalmTree and angr's bindiff
/// (which demotes constant differences to a `ConstantChange`). Keeping the
/// small ones is equally unanimous: they identify locals, arguments and struct
/// fields, and every tool that masks them loses that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConstBucket {
    /// Exactly `0`.
    Zero,
    /// Exactly `1`.
    One,
    /// Exactly `-1` (also the all-ones mask).
    MinusOne,
    /// `|v| <= `[`SMALL_CONST_ABS_MAX`]: offsets, field displacements, small bounds.
    Small,
    /// A power of two above the small threshold: alignment masks, bit fields.
    Pow2,
    /// Plausibly an address: within `[`[`POINTER_LIKE_MIN`]`, `[`POINTER_LIKE_MAX`]`]`.
    PointerLike,
    /// Everything else. The magic numbers, and the only honest thing to say
    /// about them is that they were large.
    Large,
}

impl ConstBucket {
    /// Classify a signed LLIR constant.
    ///
    /// The order of the arms is the specification: `0`, `1` and `-1` are their
    /// own buckets before magnitude is consulted, magnitude before shape, and
    /// shape (`Pow2`) before address-likeness, so a value such as `0x10000` is
    /// a power of two rather than a pointer.
    pub fn classify(value: i64) -> Self {
        match value {
            0 => return ConstBucket::Zero,
            1 => return ConstBucket::One,
            -1 => return ConstBucket::MinusOne,
            _ => {}
        }
        let magnitude = value.unsigned_abs();
        if magnitude <= SMALL_CONST_ABS_MAX as u64 {
            return ConstBucket::Small;
        }
        if magnitude.is_power_of_two() {
            return ConstBucket::Pow2;
        }
        let unsigned = value as u64;
        if (POINTER_LIKE_MIN..=POINTER_LIKE_MAX).contains(&unsigned) {
            return ConstBucket::PointerLike;
        }
        ConstBucket::Large
    }

    /// Classify an absolute virtual address, which is a pointer by construction.
    pub fn classify_addr(address: u64) -> Self {
        if (POINTER_LIKE_MIN..=POINTER_LIKE_MAX).contains(&address) {
            ConstBucket::PointerLike
        } else {
            ConstBucket::Large
        }
    }

    /// Stable token used in the label's byte encoding.
    pub fn token(self) -> &'static str {
        match self {
            ConstBucket::Zero => "c0",
            ConstBucket::One => "c1",
            ConstBucket::MinusOne => "c-1",
            ConstBucket::Small => "csmall",
            ConstBucket::Pow2 => "cpow2",
            ConstBucket::PointerLike => "cptr",
            ConstBucket::Large => "clarge",
        }
    }
}

/// What a call transfers to, with internal identity reduced to an arity.
///
/// jTrans maps internal callee names to a single `<function>` token and keeps
/// external ones, and the reason generalises: an external symbol is a stable
/// interface that survives a version bump, while an internal name is a private
/// detail that a rebuild is free to change (or inline away). The arity class is
/// what is left of an internal callee.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CalleeClass {
    /// Not a call.
    NotACall,
    /// A resolved import or PLT stub. The name is kept verbatim.
    External(String),
    /// A call inside this image, reduced to a bucketed argument count.
    Internal(ArityClass),
    /// A call through a computed value.
    Indirect,
}

impl CalleeClass {
    /// Stable token used in the label's byte encoding.
    pub fn write_token(&self, out: &mut String) {
        match self {
            CalleeClass::NotACall => out.push_str("-"),
            CalleeClass::External(name) => {
                out.push_str("ext:");
                out.push_str(name);
            }
            CalleeClass::Internal(arity) => {
                let _ = write!(out, "int:{}", arity.token());
            }
            CalleeClass::Indirect => out.push_str("ind"),
        }
    }
}

/// Bucketed argument count, capped so a long ABI may-use list cannot
/// manufacture distinctions the evidence does not support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArityClass(pub u8);

impl ArityClass {
    /// Cap above which every arity is the same class.
    pub const MAX: u8 = 6;

    /// Bucket a raw argument count.
    pub fn of(count: usize) -> Self {
        ArityClass(count.min(Self::MAX as usize) as u8)
    }

    /// Stable token used in the label's byte encoding.
    pub fn token(self) -> String {
        if self.0 >= Self::MAX {
            format!("{}+", Self::MAX)
        } else {
            self.0.to_string()
        }
    }
}

/// The operation a node performs, after source-level and naming detail is
/// projected away.
///
/// This is *not* `Op`'s discriminant: `Op::Jump`, `Op::Nop` and `Op::Unknown`
/// never produce a value node, several IR ops collapse, and the graph adds
/// kinds the IR has no operation for (a phi, a constant, a live-in, a memory
/// state).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OpKind {
    /// A register-to-register or immediate-to-register move that survived
    /// shadow elimination (its source was a constant or an address).
    Assign,
    /// An architecturally undefined value.
    Undef,
    Bin(BinOpKind),
    Un(UnOpKind),
    Cmp(CmpOpKind),
    Load,
    /// A predicated load. Distinct from `Load` because the false path performs
    /// no access at all.
    CondLoad,
    Store,
    CondStore,
    /// A computed transfer. The target *set* is CFG state, not operation state,
    /// so it is deliberately absent here.
    IndirectJump,
    CondJump,
    CondReturn,
    Call,
    Return,
    ZExt,
    SExt,
    Trunc,
    Extract,
    Concat,
    Ite,
    /// A typed opaque operation. The *name* is kept, like an external callee's:
    /// `cpuid` and `pshufb` are stable interfaces, not private details.
    Intrinsic(String),
    /// An unlifted instruction, kept as evidence that something was there.
    Unlifted,
    /// An SSA merge.
    Phi,
    /// A literal operand.
    Const,
    /// An optional operand the operation does not have: an effective address
    /// with no index register, an indirect jump with no recovered index. Kept
    /// as a node so operand positions do not shift under a positional mix.
    Absent,
    /// A live-in value defined by the caller.
    LiveIn,
    /// The memory state on entry to a block: a merge over its predecessors'
    /// exit states, or the initial state at the function entry.
    MemEntry,
    /// The memory state a writing operation produces.
    MemDef,
}

/// Binary operators, mirrored locally so the commutativity table and the label
/// encoding cannot drift from each other when [`BinOp`] gains a variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BinOpKind {
    Add,
    Sub,
    Mul,
    Div,
    LogicalAnd,
    LogicalOr,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Sar,
}

impl BinOpKind {
    /// Project an IR binary operator.
    pub fn of(op: BinOp) -> Self {
        match op {
            BinOp::Add => BinOpKind::Add,
            BinOp::Sub => BinOpKind::Sub,
            BinOp::Mul => BinOpKind::Mul,
            BinOp::Div => BinOpKind::Div,
            BinOp::LogicalAnd => BinOpKind::LogicalAnd,
            BinOp::LogicalOr => BinOpKind::LogicalOr,
            BinOp::And => BinOpKind::And,
            BinOp::Or => BinOpKind::Or,
            BinOp::Xor => BinOpKind::Xor,
            BinOp::Shl => BinOpKind::Shl,
            BinOp::Shr => BinOpKind::Shr,
            BinOp::Sar => BinOpKind::Sar,
        }
    }

    /// Stable token used in the label's byte encoding.
    pub fn token(self) -> &'static str {
        match self {
            BinOpKind::Add => "add",
            BinOpKind::Sub => "sub",
            BinOpKind::Mul => "mul",
            BinOpKind::Div => "div",
            BinOpKind::LogicalAnd => "land",
            BinOpKind::LogicalOr => "lor",
            BinOpKind::And => "and",
            BinOpKind::Or => "or",
            BinOpKind::Xor => "xor",
            BinOpKind::Shl => "shl",
            BinOpKind::Shr => "shr",
            BinOpKind::Sar => "sar",
        }
    }
}

/// Unary operators. See [`BinOpKind`] for why this is mirrored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnOpKind {
    Not,
    Neg,
}

impl UnOpKind {
    /// Project an IR unary operator.
    pub fn of(op: UnOp) -> Self {
        match op {
            UnOp::Not => UnOpKind::Not,
            UnOp::Neg => UnOpKind::Neg,
        }
    }

    /// Stable token used in the label's byte encoding.
    pub fn token(self) -> &'static str {
        match self {
            UnOpKind::Not => "not",
            UnOpKind::Neg => "neg",
        }
    }
}

/// Comparison operators. See [`BinOpKind`] for why this is mirrored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CmpOpKind {
    Eq,
    Ne,
    Ult,
    Ule,
    Slt,
    Sle,
}

impl CmpOpKind {
    /// Project an IR comparison operator.
    pub fn of(op: CmpOp) -> Self {
        match op {
            CmpOp::Eq => CmpOpKind::Eq,
            CmpOp::Ne => CmpOpKind::Ne,
            CmpOp::Ult => CmpOpKind::Ult,
            CmpOp::Ule => CmpOpKind::Ule,
            CmpOp::Slt => CmpOpKind::Slt,
            CmpOp::Sle => CmpOpKind::Sle,
        }
    }

    /// Stable token used in the label's byte encoding.
    pub fn token(self) -> &'static str {
        match self {
            CmpOpKind::Eq => "eq",
            CmpOpKind::Ne => "ne",
            CmpOpKind::Ult => "ult",
            CmpOpKind::Ule => "ule",
            CmpOpKind::Slt => "slt",
            CmpOpKind::Sle => "sle",
        }
    }
}

impl OpKind {
    /// Stable token used in the label's byte encoding.
    pub fn write_token(&self, out: &mut String) {
        match self {
            OpKind::Assign => out.push_str("assign"),
            OpKind::Undef => out.push_str("undef"),
            OpKind::Bin(op) => out.push_str(op.token()),
            OpKind::Un(op) => out.push_str(op.token()),
            OpKind::Cmp(op) => out.push_str(op.token()),
            OpKind::Load => out.push_str("load"),
            OpKind::CondLoad => out.push_str("cload"),
            OpKind::Store => out.push_str("store"),
            OpKind::CondStore => out.push_str("cstore"),
            OpKind::IndirectJump => out.push_str("ijmp"),
            OpKind::CondJump => out.push_str("cjmp"),
            OpKind::CondReturn => out.push_str("cret"),
            OpKind::Call => out.push_str("call"),
            OpKind::Return => out.push_str("ret"),
            OpKind::ZExt => out.push_str("zext"),
            OpKind::SExt => out.push_str("sext"),
            OpKind::Trunc => out.push_str("trunc"),
            OpKind::Extract => out.push_str("extract"),
            OpKind::Concat => out.push_str("concat"),
            OpKind::Ite => out.push_str("ite"),
            OpKind::Intrinsic(name) => {
                out.push_str("intr:");
                out.push_str(name);
            }
            OpKind::Unlifted => out.push_str("unlifted"),
            OpKind::Phi => out.push_str("phi"),
            OpKind::Const => out.push_str("const"),
            OpKind::Absent => out.push_str("absent"),
            OpKind::LiveIn => out.push_str("livein"),
            OpKind::MemEntry => out.push_str("mementry"),
            OpKind::MemDef => out.push_str("memdef"),
        }
    }
}

/// The complete label of one CFR-G node.
///
/// Six fields, in the order the design document states them. Everything a
/// compiler is free to choose -- which register, which block came first, what
/// address the linker picked, what the local was called -- is absent by
/// construction rather than by filtering.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeLabel {
    pub op_kind: OpKind,
    pub width: WidthClass,
    pub operand_arity: u8,
    pub value_class: ValueClass,
    /// Present only for constant-valued nodes.
    pub const_bucket: Option<ConstBucket>,
    pub callee: CalleeClass,
}

impl NodeLabel {
    /// A label for a node that is neither a constant nor a call.
    pub fn plain(
        op_kind: OpKind,
        width: WidthClass,
        operand_arity: usize,
        value_class: ValueClass,
    ) -> Self {
        NodeLabel {
            op_kind,
            width,
            operand_arity: operand_arity.min(u8::MAX as usize) as u8,
            value_class,
            const_bucket: None,
            callee: CalleeClass::NotACall,
        }
    }

    /// Apply a settings-dependent projection. Currently only `nosize`.
    pub fn apply_settings(mut self, settings: super::CfrSettings) -> Self {
        if settings.nosize {
            self.width = self.width.collapse_nosize();
        }
        self
    }

    /// The label's canonical byte encoding, which is what gets hashed.
    ///
    /// Textual rather than packed because the tuple carries two variable-length
    /// members (an intrinsic name, an external callee name) and because a
    /// readable encoding makes a wrong feature debuggable. The separator is
    /// `|`, which cannot occur in a C or Rust linkage name.
    pub fn encode(&self) -> String {
        let mut out = String::with_capacity(48);
        self.op_kind.write_token(&mut out);
        out.push('|');
        out.push_str(self.width.token());
        out.push('|');
        let _ = write!(out, "{}", self.operand_arity);
        out.push('|');
        out.push_str(self.value_class.token());
        out.push('|');
        out.push_str(self.const_bucket.map_or("-", ConstBucket::token));
        out.push('|');
        self.callee.write_token(&mut out);
        out
    }
}

/// The one-bit width every flag predicate has.
pub fn flag_width(_flag: Flag) -> WidthClass {
    WidthClass::W1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn const_buckets_follow_the_documented_precedence() {
        assert_eq!(ConstBucket::classify(0), ConstBucket::Zero);
        assert_eq!(ConstBucket::classify(1), ConstBucket::One);
        assert_eq!(ConstBucket::classify(-1), ConstBucket::MinusOne);
        assert_eq!(ConstBucket::classify(8), ConstBucket::Small);
        assert_eq!(ConstBucket::classify(-24), ConstBucket::Small);
        assert_eq!(ConstBucket::classify(5000), ConstBucket::Small);
        // Above the small threshold, shape wins over address-likeness.
        assert_eq!(ConstBucket::classify(0x10000), ConstBucket::Pow2);
        assert_eq!(ConstBucket::classify(0x4011a3), ConstBucket::PointerLike);
        assert_eq!(
            ConstBucket::classify(0x5851_f42d_4c95_7f2d_u64 as i64),
            ConstBucket::Large
        );
    }

    #[test]
    fn nosize_collapses_four_bytes_and_up_but_not_below() {
        assert_eq!(WidthClass::W1.collapse_nosize(), WidthClass::W1);
        assert_eq!(WidthClass::W8.collapse_nosize(), WidthClass::W8);
        assert_eq!(WidthClass::W16.collapse_nosize(), WidthClass::W16);
        assert_eq!(WidthClass::W32.collapse_nosize(), WidthClass::WGe4);
        assert_eq!(WidthClass::W64.collapse_nosize(), WidthClass::WGe4);
        assert_eq!(WidthClass::W128.collapse_nosize(), WidthClass::WGe4);
        assert_eq!(WidthClass::Unknown.collapse_nosize(), WidthClass::Unknown);
    }

    #[test]
    fn widths_round_up_to_the_next_machine_class() {
        assert_eq!(WidthClass::from_bits(24), WidthClass::W32);
        assert_eq!(WidthClass::from_bits(3), WidthClass::W8);
        assert_eq!(WidthClass::from_bits(0), WidthClass::Unknown);
    }

    #[test]
    fn a_label_encoding_never_carries_a_register_name() {
        let label = NodeLabel::plain(
            OpKind::Bin(BinOpKind::Add),
            WidthClass::W64,
            2,
            ValueClass::Derived,
        );
        assert_eq!(label.encode(), "add|w64|2|derived|-|-");
    }
}
