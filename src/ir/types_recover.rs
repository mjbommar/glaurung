//! First-cut type recovery for VRegs in an [`LlirFunction`].
//!
//! v0 scope — deliberately tiny, but useful:
//!
//! * Registers used as the base of a `Load`/`Store` memory operand are
//!   classified as **pointers**. The inferred pointee width comes from the
//!   memory access size.
//! * Registers used solely as shift counts are tagged **unsigned integer**.
//! * Registers that flow into a `CallTarget::Direct` as the first argument
//!   register (by convention x86-64 SysV: `rdi`, AArch64: `x0`) keep their
//!   inferred type if one was set earlier — this is just a pass-through
//!   hook for future argument-type inference.
//!
//! The output is a [`TypeMap`] keyed by [`VReg`]. Later passes can refine
//! it; the AST printer can consume it to print `int`/`char*`/`bool` instead
//! of raw register names.
//!
//! This pass reads only the LLIR — it does not require SSA form — which
//! keeps it cheap and composable. Passes that need SSA precision can
//! consume [`crate::ir::ssa::SsaInfo`] and re-run on a per-version basis.

use std::collections::{HashMap, HashSet};

use crate::ir::ssa::{SsaInfo, SsaValue};
use crate::ir::types::{BinOp, LlirFunction, Op, VReg, Value};
use crate::ir::use_def::{def_uses, InstrAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeHint {
    /// A pointer; `width` records the access size of the last memory
    /// operation performed through it (1/2/4/8 bytes).
    Pointer { pointee_width: u8 },
    /// Signed/unsigned integer — distinguished by context (shifts tagged
    /// unsigned, arithmetic compared against signed constants tagged signed).
    Int { signed: bool, width: u8 },
    /// Value used as a 0/1 boolean (compared equal to zero).
    BoolLike,
    /// The value is used by [`Op::Call`] as an indirect call target, so it
    /// is likely a code pointer.
    CodePointer,
}

#[derive(Debug, Default, Clone)]
pub struct TypeMap {
    inner: HashMap<VReg, TypeHint>,
}

impl TypeMap {
    pub fn get(&self, v: &VReg) -> Option<TypeHint> {
        self.inner.get(v).copied()
    }
    pub fn iter(&self) -> impl Iterator<Item = (&VReg, &TypeHint)> {
        self.inner.iter()
    }
    pub fn len(&self) -> usize {
        self.inner.len()
    }
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Public wrapper around [`Self::upsert`] so other modules (e.g. the
    /// Python binding's type-map remapper) can build a `TypeMap`
    /// incrementally from outside this crate's module.
    pub fn upsert_public(&mut self, reg: VReg, new: TypeHint) {
        self.upsert(reg, new)
    }

    /// Refine a fact after value-keyed analysis identifies the exact value that
    /// occupies this rendered role. This is deliberately distinct from the
    /// union-style `upsert`: SSA identity decides scalar-vs-address class while
    /// the older operation-level analysis retains richer scalar signedness.
    pub(crate) fn refine_from_value(&mut self, reg: VReg, hint: TypeHint) {
        let current = self.inner.get(&reg).copied();
        let replace = match (current, hint) {
            (None, _) => true,
            // Per-value identity is decisive when raw-register union confused a
            // scalar lifetime with an address-bearing lifetime (or vice versa).
            (
                Some(TypeHint::Int { .. } | TypeHint::BoolLike),
                TypeHint::Pointer { .. } | TypeHint::CodePointer,
            )
            | (
                Some(TypeHint::Pointer { .. } | TypeHint::CodePointer),
                TypeHint::Int { .. } | TypeHint::BoolLike,
            ) => true,
            // Exact-value memory evidence may refine the access width or
            // distinguish data from code pointers.
            (
                Some(TypeHint::Pointer { .. } | TypeHint::CodePointer),
                TypeHint::Pointer { .. } | TypeHint::CodePointer,
            ) => true,
            // The older recovery contains richer scalar signedness evidence
            // from operation context (e.g. SHR/SAR). Value identity alone is
            // not a reason to throw that fact away.
            _ => false,
        };
        if replace {
            self.inner.insert(reg, hint);
        }
    }

    /// Replace an existing integer width with an ABI-mandated width while
    /// preserving signedness. This is intentionally narrower than `upsert`:
    /// ordinary evidence merging prefers a precise sub-register width, whereas
    /// a later proof that the value's high bits are consumed must be allowed to
    /// restore the complete incoming/return eightbyte. Semantic pointer hints
    /// are never overwritten.
    pub(crate) fn force_int_width(&mut self, reg: VReg, width: u8) {
        if let Some(TypeHint::Int { signed, .. }) = self.inner.get(&reg).copied() {
            self.inner.insert(reg, TypeHint::Int { signed, width });
        }
    }

    /// Replace an existing integer's signedness while preserving its recovered
    /// width. A signed AST comparison is stronger evidence than an earlier
    /// zero-extension/index use, but it is not evidence that a pointer or code
    /// pointer should become an integer.
    pub(crate) fn force_int_signedness(&mut self, reg: VReg, signed: bool) {
        if let Some(TypeHint::Int { width, .. }) = self.inner.get(&reg).copied() {
            self.inner.insert(reg, TypeHint::Int { signed, width });
        }
    }

    /// Replace a stale pointee width after the prepared AST proves that every
    /// direct access through this value has one different width. Raw-register
    /// recovery can merge unrelated SSA-era uses of the same architectural
    /// register; the final value identity is stronger evidence.
    pub(crate) fn force_pointer_width(&mut self, reg: VReg, pointee_width: u8) {
        if matches!(self.inner.get(&reg), Some(TypeHint::Pointer { .. })) {
            self.inner.insert(reg, TypeHint::Pointer { pointee_width });
        }
    }

    /// Replace even a stale pointer classification after a later value-flow
    /// proof establishes that every definition reaching this role is scalar.
    /// Callers must perform that proof on the prepared, value-keyed AST; raw
    /// register evidence alone is deliberately not strong enough to use this.
    pub(crate) fn force_scalar_int(&mut self, reg: VReg, signed: bool, width: u8) {
        self.inner.insert(reg, TypeHint::Int { signed, width });
    }

    /// Union-style update: only overwrite when `new` is strictly more
    /// specific than the current entry. Pointers beat ints; specific widths
    /// beat zero-width entries; bool beats nothing.
    fn upsert(&mut self, reg: VReg, new: TypeHint) {
        let keep = merge_type_hint(self.inner.get(&reg).copied(), new);
        self.inner.insert(reg, keep);
    }
}

/// Type facts keyed by the value a particular definition produced, rather
/// than by the architectural register that happened to carry it. This is the
/// substrate used by Ghidra's Varnodes and Kuna's per-write Varnode arena; it
/// prevents unrelated register lifetimes from poisoning each other's types.
#[derive(Debug, Default, Clone)]
pub struct TypeMapV {
    inner: HashMap<SsaValue, TypeHint>,
    parameter_refinements: HashMap<SsaValue, TypeHint>,
}

impl TypeMapV {
    pub fn get(&self, value: &SsaValue) -> Option<TypeHint> {
        self.inner.get(value).copied()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&SsaValue, &TypeHint)> {
        self.inner.iter()
    }

    fn upsert(&mut self, value: SsaValue, hint: TypeHint) -> bool {
        let before = self.inner.get(&value).copied();
        let merged = merge_type_hint(before, hint);
        self.inner.insert(value, merged);
        before != Some(merged)
    }

    fn upsert_parameter_refinement(&mut self, value: SsaValue, hint: TypeHint) -> bool {
        let before = self.parameter_refinements.get(&value).copied();
        let merged = merge_type_hint(before, hint);
        self.parameter_refinements.insert(value, merged);
        before != Some(merged)
    }

    /// Project only entry definitions back to a compatibility map. This is a
    /// lossless projection for ABI parameters: version zero is the unique
    /// caller-supplied value, while later scratch lifetimes remain excluded.
    pub fn live_in_types(&self) -> TypeMap {
        let mut out = TypeMap::default();
        for (value, hint) in &self.inner {
            if value.version == 0 {
                out.upsert(value.base.clone(), *hint);
            }
        }
        out
    }

    /// Entry-value facts strong enough to change a rendered parameter today.
    ///
    /// The full value map is analysis evidence, but output-facing prototype
    /// recovery is not yet a fixed point with function boundaries and callee
    /// prototypes. Until that architecture lands, qualify only the concrete
    /// O0 chain `live-in -> frame spill -> reload -> dereference`, and require
    /// two independently qualified entry values before changing the prototype.
    /// A lone address-taken scalar can otherwise acquire pointer evidence from
    /// an over-discovered tail. Projecting every live-in fact can also replace a
    /// better legacy prototype with evidence from an unknown direct callee.
    pub fn parameter_refinements(&self) -> TypeMap {
        let mut out = TypeMap::default();
        if self
            .parameter_refinements
            .keys()
            .filter(|value| value.version == 0)
            .count()
            < 2
        {
            return out;
        }
        for (value, hint) in &self.parameter_refinements {
            if value.version == 0 {
                out.upsert(value.base.clone(), *hint);
            }
        }
        out
    }
}

fn merge_type_hint(current: Option<TypeHint>, new: TypeHint) -> TypeHint {
    match (current, new) {
        (None, _) => new,
        // Pointer / CodePointer are the strongest semantic classifications.
        (
            Some(TypeHint::Int { .. }) | Some(TypeHint::BoolLike),
            TypeHint::Pointer { .. } | TypeHint::CodePointer,
        ) => new,
        (Some(TypeHint::Pointer { pointee_width: a }), TypeHint::Pointer { pointee_width: b })
            if b > a =>
        {
            new
        }
        (Some(TypeHint::Pointer { .. }) | Some(TypeHint::CodePointer), _) => current.unwrap(),
        (Some(TypeHint::Int { .. }), TypeHint::BoolLike) => new,
        (Some(TypeHint::BoolLike), TypeHint::Int { .. }) => current.unwrap(),
        (Some(TypeHint::BoolLike), TypeHint::BoolLike) => new,
        (
            Some(TypeHint::Int {
                signed: cs,
                width: cw,
            }),
            TypeHint::Int {
                signed: ns,
                width: nw,
            },
        ) => TypeHint::Int {
            signed: cs && ns,
            width: combine_int_width(cw, nw),
        },
    }
}

/// Merge two candidate integer widths. Register sub-names give the true operand
/// width (`edi`=4), while the arithmetic-result fallback conservatively assumes
/// 8; when they disagree the narrower, more-specific width wins. Zero (unknown)
/// defers to the other.
fn combine_int_width(a: u8, b: u8) -> u8 {
    match (a, b) {
        (0, x) | (x, 0) => x,
        (a, b) => a.min(b),
    }
}

fn classify_int_default() -> TypeHint {
    TypeHint::Int {
        signed: true,
        width: 8,
    }
}

/// The byte width a physical register name implies (`edi`->4, `rdi`->8,
/// `w0`->4, `x0`->8, `di`->2, `dil`->1). Falls back to 8 for unknown names.
fn reg_width_bytes(v: &VReg) -> u8 {
    if let VReg::Phys(n) = v {
        if let Some(w) = crate::ir::types::phys_reg_width(n) {
            return (w.bits() / 8).max(1) as u8;
        }
    }
    8
}

/// A signed integer hint whose width comes from the register's sub-name. This
/// is the single biggest type-recovery signal at `-O0`: an `int` argument is
/// spilled through the 32-bit view (`edi`/`w0`) while a `long`/pointer uses the
/// 64-bit view (`rdi`/`x0`).
fn int_for_reg(v: &VReg) -> TypeHint {
    TypeHint::Int {
        signed: true,
        width: reg_width_bytes(v),
    }
}

/// Tag every physical register that carries a value in `op` with a
/// width-appropriate signed-int hint. The `upsert` policy keeps a more-specific
/// classification (pointer / bool / code-pointer / narrower width), so this only
/// fills in the width for registers nothing else has typed.
fn tag_value_regs(op: &Op, tm: &mut TypeMap) {
    let tag = |val: &Value, tm: &mut TypeMap| {
        if let Value::Reg(r @ VReg::Phys(_)) = val {
            tm.upsert(r.clone(), int_for_reg(r));
        }
    };
    let bytes = |width: crate::ir::types::Width| width.bytes().min(u8::MAX as u16) as u8;
    match op {
        // Jumps through a computed value; the target is an address, and the
        // width hint this pass applies would be wrong for one.
        Op::IndirectJump { .. } => {}
        Op::Assign { dst, src } => {
            if let VReg::Phys(_) = dst {
                tm.upsert(dst.clone(), int_for_reg(dst));
            }
            tag(src, tm);
        }
        Op::Store { src, .. } => tag(src, tm),
        Op::Bin { dst, lhs, rhs, .. } => {
            if let VReg::Phys(_) = dst {
                tm.upsert(dst.clone(), int_for_reg(dst));
            }
            tag(lhs, tm);
            tag(rhs, tm);
        }
        Op::Un { dst, src, .. } => {
            if let VReg::Phys(_) = dst {
                tm.upsert(dst.clone(), int_for_reg(dst));
            }
            tag(src, tm);
        }
        Op::Cmp { lhs, rhs, .. } => {
            tag(lhs, tm);
            tag(rhs, tm);
        }
        Op::ZExt { dst, src, from, to } => {
            if let VReg::Phys(_) = dst {
                tm.upsert(
                    dst.clone(),
                    TypeHint::Int {
                        signed: false,
                        width: bytes(*to),
                    },
                );
            }
            if let Value::Reg(src @ VReg::Phys(_)) = src {
                tm.upsert(
                    src.clone(),
                    TypeHint::Int {
                        signed: true,
                        width: bytes(*from),
                    },
                );
            }
        }
        Op::SExt { dst, src, from, to } => {
            if let VReg::Phys(_) = dst {
                tm.upsert(
                    dst.clone(),
                    TypeHint::Int {
                        signed: true,
                        width: bytes(*to),
                    },
                );
            }
            if let Value::Reg(src @ VReg::Phys(_)) = src {
                tm.upsert(
                    src.clone(),
                    TypeHint::Int {
                        signed: true,
                        width: bytes(*from),
                    },
                );
            }
        }
        Op::Trunc { dst, src, from, to } => {
            if let VReg::Phys(_) = dst {
                tm.upsert(
                    dst.clone(),
                    TypeHint::Int {
                        signed: true,
                        width: bytes(*to),
                    },
                );
            }
            if let Value::Reg(src @ VReg::Phys(_)) = src {
                tm.upsert(
                    src.clone(),
                    TypeHint::Int {
                        signed: true,
                        width: bytes(*from),
                    },
                );
            }
        }
        _ => {}
    }
}

/// True for a frame-relative base register (`rbp`/`rsp` on x86-64,
/// `x29`/`sp`/`w29` on AArch64) — the anchors `-O0` code spills locals against.
fn is_frame_base(v: &VReg) -> bool {
    matches!(
        v,
        VReg::Phys(n)
            if matches!(n.as_str(), "rbp" | "rsp" | "ebp" | "esp" | "x29" | "sp" | "w29")
    )
}

/// See the call site in [`recover_types`]. Two forward passes over `lf`:
///   1. record `slot -> register` for each spill store `[frame+disp] = reg`;
///   2. for each reload `reg = [frame+disp]` whose destination is already a
///      pointer in `tm`, propagate that pointer back to the spilled register.
fn propagate_spill_slot_pointers(lf: &LlirFunction, tm: &mut TypeMap) {
    // slot (frame-base name, disp) -> the register most recently spilled there.
    let mut spilled_from: HashMap<(String, i64), VReg> = HashMap::new();
    for block in &lf.blocks {
        for ins in &block.instrs {
            if let Op::Store {
                addr,
                src: Value::Reg(r @ VReg::Phys(_)),
            } = &ins.op
            {
                if let Some(base) = &addr.base {
                    if is_frame_base(base) && addr.index.is_none() {
                        if let VReg::Phys(bn) = base {
                            spilled_from.insert((bn.clone(), addr.disp), r.clone());
                        }
                    }
                }
            }
        }
    }
    if spilled_from.is_empty() {
        return;
    }
    for block in &lf.blocks {
        for ins in &block.instrs {
            if let Op::Load { dst, addr } = &ins.op {
                if let Some(base) = &addr.base {
                    if is_frame_base(base) && addr.index.is_none() {
                        if let VReg::Phys(bn) = base {
                            if let (Some(src_reg), Some(TypeHint::Pointer { pointee_width })) =
                                (spilled_from.get(&(bn.clone(), addr.disp)), tm.get(dst))
                            {
                                tm.upsert(src_reg.clone(), TypeHint::Pointer { pointee_width });
                            }
                        }
                    }
                }
            }
        }
    }
}

/// The registers that carry the return value under `cc`, widest first.
fn return_reg_names(cc: crate::ir::call_args::CallConv) -> &'static [&'static str] {
    use crate::ir::call_args::CallConv;
    match cc {
        CallConv::SysVAmd64 | CallConv::Win64 => &["rax", "eax", "ax", "al"],
        CallConv::Cdecl32 => &["rax", "eax", "ax", "al"],
        CallConv::Aarch64 => &["x0", "w0"],
        CallConv::Arm => &["r0"],
    }
}

/// The destination register an op writes to (if it writes a value register).
fn op_dst_reg(op: &Op) -> Option<&VReg> {
    match op {
        Op::Assign { dst, .. }
        | Op::Bin { dst, .. }
        | Op::Un { dst, .. }
        | Op::Load { dst, .. } => Some(dst),
        _ => None,
    }
}

/// Correct the return register's type from the value that is actually
/// *returned*, not the flow-insensitive union of every use of the ABI return
/// register. At `-O0` `rax` is heavily reused as scratch — often as a pointer
/// base while computing an integer result — so the union wrongly reports a
/// pointer return (e.g. `char *str_len(...)` that really returns `int`).
///
/// Key fact: a value produced into a **sub-64-bit** view of the return register
/// (`eax`/`ax`/`al`, `w0`) cannot be a 64-bit pointer. So when the *last*
/// definition of the return register in program order writes such a narrow
/// view, we overwrite every return-register alias with that concrete integer
/// width, clearing any spurious pointer classification. A genuine pointer
/// return writes the full 64-bit register and is left untouched.
fn refine_return_type(lf: &LlirFunction, tm: &mut TypeMap, cc: crate::ir::call_args::CallConv) {
    let ret_names = return_reg_names(cc);
    let mut last_dst: Option<VReg> = None;
    for block in &lf.blocks {
        for ins in &block.instrs {
            if let Some(VReg::Phys(n)) = op_dst_reg(&ins.op) {
                if ret_names.contains(&n.as_str()) {
                    last_dst = Some(VReg::phys(n));
                }
            }
        }
    }
    let Some(dst) = last_dst else {
        return;
    };
    let w = reg_width_bytes(&dst);
    if w == 0 || w >= 8 {
        // Full-width (or unknown) last definition: could legitimately be a
        // pointer or a `long`; leave the recovered classification alone.
        return;
    }
    let signed = match tm.get(&dst) {
        Some(TypeHint::Int { signed, .. }) => signed,
        _ => true,
    };
    let hint = TypeHint::Int { signed, width: w };
    for n in ret_names {
        let key = VReg::phys(*n);
        if tm.inner.contains_key(&key) {
            tm.inner.insert(key, hint);
        }
    }
}

/// Production entry point: [`recover_types`] plus the calling-convention-aware
/// return-type correction. Callers that know the ABI (the Python bindings)
/// should prefer this over the bare [`recover_types`].
pub fn recover_types_for(lf: &LlirFunction, cc: crate::ir::call_args::CallConv) -> TypeMap {
    let mut tm = recover_types(lf);
    refine_return_type(lf, &mut tm, cc);
    tm
}

/// Registers whose value is a pure *offset / scaled index* — the index side of
/// an `base + index` address computation, never the pointer base. A register is
/// an offset if it is defined by a multiply or shift (`i * 4`, `i << 2`), or by
/// an add/sub that only combines constants and other offset registers
/// (`0 + i*4`, the `-O0` `lea` idiom). Computed to a fixpoint.
fn offset_registers(lf: &LlirFunction) -> std::collections::HashSet<VReg> {
    let mut offsets: std::collections::HashSet<VReg> = std::collections::HashSet::new();
    let is_off = |offsets: &std::collections::HashSet<VReg>, v: &Value| match v {
        Value::Const(_) => true,
        Value::Reg(r) => offsets.contains(r),
        Value::Addr(_) => false,
    };
    for _ in 0..8 {
        let mut grew = false;
        for block in &lf.blocks {
            for ins in &block.instrs {
                if let Op::Bin { op, dst, lhs, rhs } = &ins.op {
                    let dst_is_off = match op {
                        // A multiply/shift result is a scaled index.
                        BinOp::Mul | BinOp::Shl => true,
                        // An add/sub is an offset only if *both* sides are.
                        BinOp::Add | BinOp::Sub => is_off(&offsets, lhs) && is_off(&offsets, rhs),
                        _ => false,
                    };
                    if dst_is_off && offsets.insert(dst.clone()) {
                        grew = true;
                    }
                }
            }
        }
        if !grew {
            break;
        }
    }
    offsets
}

/// Registers that hold a *reload of a spilled value* — the destination of a
/// `Load` from a frame-base slot with no index (`rax = [rbp-24]`). At `-O0` a
/// spilled pointer argument is reloaded this way before each dereference, so a
/// reload operand of an address `add` is the pointer base (the other operand is
/// the index). Feeding these to [`propagate_spill_slot_pointers`] then carries
/// the pointer type back to the incoming argument register.
fn frame_slot_reloads(lf: &LlirFunction) -> std::collections::HashSet<VReg> {
    let mut reloads = std::collections::HashSet::new();
    for block in &lf.blocks {
        for ins in &block.instrs {
            if let Op::Load { dst, addr } = &ins.op {
                if let Some(base) = &addr.base {
                    if is_frame_base(base) && addr.index.is_none() {
                        reloads.insert(dst.clone());
                    }
                }
            }
        }
    }
    reloads
}

/// Propagate pointer-ness backward through address arithmetic: if a register
/// `p` is used as a pointer (dereferenced) and is defined by `p = base + off`,
/// then `base` is a pointer too. This recovers `T *` argument types once the
/// spill-slot has been coalesced away and the parameter is used directly as
/// `*(base + i*scale)` — the shape value-numbering produces for `a[i]`. Iterated
/// to a fixpoint so a chain of address additions all resolve.
///
/// The base is identified structurally, not by existing type (a spilled pointer
/// parameter looks like a plain `long` until this pass runs, which a type-based
/// heuristic gets backwards). Two complementary signals:
///  * the *offset* operand is a constant or a scaled-index register
///    ([`offset_registers`]) — so the other operand is the base; and
///  * the *base* operand is a frame-slot reload ([`frame_slot_reloads`]) — the
///    reloaded spilled pointer — so the other operand is the index.
fn propagate_pointer_arithmetic(lf: &LlirFunction, tm: &mut TypeMap) {
    let offsets = offset_registers(lf);
    let reloads = frame_slot_reloads(lf);
    let is_offset = |v: &Value| match v {
        Value::Const(_) => true,
        Value::Reg(r) => offsets.contains(r),
        Value::Addr(_) => false,
    };
    let is_reload = |v: &Value| matches!(v, Value::Reg(r) if reloads.contains(r));
    for _ in 0..8 {
        let mut changed = false;
        for block in &lf.blocks {
            for ins in &block.instrs {
                if let Op::Bin {
                    op: BinOp::Add,
                    dst,
                    lhs,
                    rhs,
                } = &ins.op
                {
                    let pw = match tm.get(dst) {
                        Some(TypeHint::Pointer { pointee_width }) => pointee_width,
                        _ => continue,
                    };
                    // Prefer the reload signal (base is the reloaded pointer);
                    // fall back to the offset signal (base is the non-offset
                    // operand). Both agree in the common `*(reload + i*scale)`.
                    let base = if is_reload(lhs) && !is_reload(rhs) {
                        Some(lhs)
                    } else if is_reload(rhs) && !is_reload(lhs) {
                        Some(rhs)
                    } else if is_offset(rhs) && !is_offset(lhs) {
                        Some(lhs)
                    } else if is_offset(lhs) && !is_offset(rhs) {
                        Some(rhs)
                    } else {
                        // Can't tell base from index; leave it alone.
                        None
                    };
                    if let Some(Value::Reg(r)) = base {
                        // Don't downgrade / re-tag an already-pointer register.
                        if !matches!(tm.get(r), Some(TypeHint::Pointer { .. })) {
                            let before = tm.get(r);
                            tm.upsert(r.clone(), TypeHint::Pointer { pointee_width: pw });
                            if tm.get(r) != before {
                                changed = true;
                            }
                        }
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }
}

/// Raw operands paired with the SSA value each occurrence reads or writes.
/// Keeping the raw operand beside the canonical value is important: the raw
/// spelling retains machine width (`edi` is four bytes), while [`SsaValue`]
/// supplies the cross-view identity (`edi` and `rdi` are the same storage).
struct InstructionValues {
    def: Option<(VReg, SsaValue)>,
    uses: Vec<Option<(VReg, SsaValue)>>,
}

fn instruction_values(lf: &LlirFunction, ssa: &SsaInfo, addr: InstrAddr) -> InstructionValues {
    let op = &lf.blocks[addr.block_idx].instrs[addr.instr_idx].op;
    let (raw_def, raw_uses) = def_uses(op);
    let def = raw_def.zip(ssa.def_value(lf, addr));
    let uses = raw_uses
        .into_iter()
        .enumerate()
        .map(|(index, raw)| ssa.use_value(lf, addr, index).map(|value| (raw, value)))
        .collect();
    InstructionValues { def, uses }
}

fn operand_value(
    operand: &Value,
    values: &InstructionValues,
    cursor: &mut usize,
) -> Option<SsaValue> {
    if !matches!(operand, Value::Reg(_)) {
        return None;
    }
    let value = values
        .uses
        .get(*cursor)
        .and_then(|entry| entry.as_ref())
        .map(|(_, value)| value.clone());
    *cursor += 1;
    value
}

fn frame_slot(addr: &crate::ir::types::MemOp) -> Option<(String, i64)> {
    if addr.index.is_some() {
        return None;
    }
    match addr.base.as_ref() {
        Some(base @ VReg::Phys(name)) if is_frame_base(base) => Some((name.clone(), addr.disp)),
        _ => None,
    }
}

fn unify_values(tm: &mut TypeMapV, a: &SsaValue, b: &SsaValue) -> bool {
    let a_hint = tm.get(a);
    let b_hint = tm.get(b);
    let mut changed = false;
    if let Some(hint) = a_hint {
        changed |= tm.upsert(b.clone(), hint);
    }
    if let Some(hint) = b_hint {
        changed |= tm.upsert(a.clone(), hint);
    }
    changed
}

/// Values participating in a phi whose result can reach a real instruction
/// use. Our SSA builder deliberately places unpruned phis; treating a dead phi
/// as a type-equivalence edge merges unrelated storage lifetimes at CFG exits.
fn live_phi_values(lf: &LlirFunction, ssa: &SsaInfo) -> HashSet<SsaValue> {
    let mut live = HashSet::new();
    for (block_idx, block) in lf.blocks.iter().enumerate() {
        for (instr_idx, _) in block.instrs.iter().enumerate() {
            let values = instruction_values(
                lf,
                ssa,
                InstrAddr {
                    block_idx,
                    instr_idx,
                },
            );
            live.extend(values.uses.into_iter().flatten().map(|(_, value)| value));
        }
    }
    for _ in 0..ssa.phis.len().max(1) {
        let mut grew = false;
        for phi in &ssa.phis {
            let result = SsaValue {
                base: phi.base.clone(),
                version: phi.dst_version,
            };
            if !live.contains(&result) {
                continue;
            }
            for (_, version) in &phi.incoming {
                grew |= live.insert(SsaValue {
                    base: phi.base.clone(),
                    version: *version,
                });
            }
        }
        if !grew {
            break;
        }
    }
    live
}

/// Recover type facts per SSA definition.
///
/// The inference rules deliberately mirror the established raw-register pass,
/// but all propagation edges carry [`SsaValue`] identities. Copies and phis
/// unify values, stack spills preserve the exact value stored, and pointer
/// arithmetic walks definition/use edges. A later constant definition can
/// therefore be demoted without erasing an earlier pointer in the same
/// architectural register.
pub fn recover_types_valued(lf: &LlirFunction, ssa: &SsaInfo) -> TypeMapV {
    let mut tm = TypeMapV::default();
    let mut constant_defs: HashMap<SsaValue, TypeHint> = HashMap::new();
    let mut copy_edges: Vec<(SsaValue, SsaValue)> = Vec::new();
    let mut reloads: HashSet<SsaValue> = HashSet::new();
    let mut live_in_spills: HashMap<(String, i64), Vec<SsaValue>> = HashMap::new();
    let live_phi_values = live_phi_values(lf, ssa);

    // Seed local facts and record explicit value-flow edges.
    for (block_idx, block) in lf.blocks.iter().enumerate() {
        for (instr_idx, ins) in block.instrs.iter().enumerate() {
            let addr = InstrAddr {
                block_idx,
                instr_idx,
            };
            let values = instruction_values(lf, ssa, addr);

            // Width evidence comes from the raw view at this occurrence.
            if let Some((raw, value)) = &values.def {
                if matches!(raw, VReg::Phys(_)) {
                    tm.upsert(value.clone(), int_for_reg(raw));
                }
            }
            for (raw, value) in values.uses.iter().flatten() {
                if matches!(raw, VReg::Phys(_)) {
                    tm.upsert(value.clone(), int_for_reg(raw));
                }
            }

            match &ins.op {
                Op::Assign { src, .. } => {
                    if let (Some((_, dst)), Value::Reg(_)) = (&values.def, src) {
                        if let Some((_, source)) = values.uses.first().and_then(Option::as_ref) {
                            copy_edges.push((dst.clone(), source.clone()));
                        }
                    } else if matches!(src, Value::Const(_)) {
                        if let Some((raw, dst)) = &values.def {
                            constant_defs.insert(dst.clone(), int_for_reg(raw));
                        }
                    }
                }
                Op::Load { addr, .. } => {
                    let mut use_index = 0usize;
                    if addr.base.is_some() {
                        if let Some((_, base)) =
                            values.uses.get(use_index).and_then(|entry| entry.as_ref())
                        {
                            tm.upsert(
                                base.clone(),
                                TypeHint::Pointer {
                                    pointee_width: addr.size.max(1),
                                },
                            );
                        }
                        use_index += 1;
                    }
                    if addr.index.is_some() {
                        if let Some((raw, index)) =
                            values.uses.get(use_index).and_then(|entry| entry.as_ref())
                        {
                            tm.upsert(
                                index.clone(),
                                TypeHint::Int {
                                    signed: false,
                                    width: reg_width_bytes(raw),
                                },
                            );
                        }
                    }
                    if frame_slot(addr).is_some() {
                        if let Some((_, dst)) = &values.def {
                            reloads.insert(dst.clone());
                        }
                    }
                }
                Op::Store { addr, .. } => {
                    let mut use_index = 0usize;
                    if addr.base.is_some() {
                        if let Some((_, base)) =
                            values.uses.get(use_index).and_then(|entry| entry.as_ref())
                        {
                            tm.upsert(
                                base.clone(),
                                TypeHint::Pointer {
                                    pointee_width: addr.size.max(1),
                                },
                            );
                        }
                        use_index += 1;
                    }
                    if addr.index.is_some() {
                        if let Some((raw, index)) =
                            values.uses.get(use_index).and_then(|entry| entry.as_ref())
                        {
                            tm.upsert(
                                index.clone(),
                                TypeHint::Int {
                                    signed: false,
                                    width: reg_width_bytes(raw),
                                },
                            );
                        }
                        use_index += 1;
                    }
                    if let Some(slot) = frame_slot(addr) {
                        if let Some((_, source)) =
                            values.uses.get(use_index).and_then(|entry| entry.as_ref())
                        {
                            // This projection targets caller-supplied parameters.
                            // Preserve their entry provenance instead of letting a
                            // later loop update to the same slot overwrite it.
                            if source.version == 0 && matches!(source.base, VReg::Phys(_)) {
                                let sources = live_in_spills.entry(slot).or_default();
                                if !sources.contains(source) {
                                    sources.push(source.clone());
                                }
                            }
                        }
                    }
                }
                Op::Call {
                    target: crate::ir::types::CallTarget::Indirect(Value::Reg(_)),
                    ..
                }
                | Op::IndirectJump {
                    target: Value::Reg(_),
                } => {
                    if let Some((_, target)) = values.uses.first().and_then(Option::as_ref) {
                        tm.upsert(target.clone(), TypeHint::CodePointer);
                    }
                }
                Op::Bin {
                    op: BinOp::Shr,
                    lhs,
                    rhs,
                    ..
                } => {
                    if let Some((raw, dst)) = &values.def {
                        tm.upsert(
                            dst.clone(),
                            TypeHint::Int {
                                signed: false,
                                width: reg_width_bytes(raw),
                            },
                        );
                    }
                    let mut cursor = 0;
                    if let Some(lhs_value) = operand_value(lhs, &values, &mut cursor) {
                        let raw = match lhs {
                            Value::Reg(raw) => raw,
                            _ => unreachable!(),
                        };
                        tm.upsert(
                            lhs_value,
                            TypeHint::Int {
                                signed: false,
                                width: reg_width_bytes(raw),
                            },
                        );
                    }
                    if let Some(rhs_value) = operand_value(rhs, &values, &mut cursor) {
                        let raw = match rhs {
                            Value::Reg(raw) => raw,
                            _ => unreachable!(),
                        };
                        tm.upsert(
                            rhs_value,
                            TypeHint::Int {
                                signed: false,
                                width: reg_width_bytes(raw),
                            },
                        );
                    }
                }
                Op::Bin {
                    op: BinOp::Shl | BinOp::Sar,
                    lhs,
                    rhs,
                    ..
                } => {
                    let mut cursor = 0;
                    let _ = operand_value(lhs, &values, &mut cursor);
                    if let Some(rhs_value) = operand_value(rhs, &values, &mut cursor) {
                        let raw = match rhs {
                            Value::Reg(raw) => raw,
                            _ => unreachable!(),
                        };
                        tm.upsert(
                            rhs_value,
                            TypeHint::Int {
                                signed: false,
                                width: reg_width_bytes(raw),
                            },
                        );
                    }
                }
                Op::ZExt { src, from, to, .. }
                | Op::SExt { src, from, to, .. }
                | Op::Trunc { src, from, to, .. } => {
                    let signed = !matches!(&ins.op, Op::ZExt { .. });
                    if let Some((_, dst)) = &values.def {
                        tm.upsert(
                            dst.clone(),
                            TypeHint::Int {
                                signed,
                                width: to.bytes().min(u8::MAX as u16) as u8,
                            },
                        );
                    }
                    let mut cursor = 0;
                    if let Some(source) = operand_value(src, &values, &mut cursor) {
                        tm.upsert(
                            source,
                            TypeHint::Int {
                                signed: true,
                                width: from.bytes().min(u8::MAX as u16) as u8,
                            },
                        );
                    }
                }
                _ => {}
            }
        }
    }

    // Compute scaled-index/offset values using SSA operands, not register names.
    let mut offsets: HashSet<SsaValue> = HashSet::new();
    for _ in 0..8 {
        let mut grew = false;
        for (block_idx, block) in lf.blocks.iter().enumerate() {
            for (instr_idx, ins) in block.instrs.iter().enumerate() {
                let Op::Bin { op, lhs, rhs, .. } = &ins.op else {
                    continue;
                };
                let addr = InstrAddr {
                    block_idx,
                    instr_idx,
                };
                let values = instruction_values(lf, ssa, addr);
                let Some((_, dst)) = &values.def else {
                    continue;
                };
                let mut cursor = 0;
                let lhs_value = operand_value(lhs, &values, &mut cursor);
                let rhs_value = operand_value(rhs, &values, &mut cursor);
                let is_offset = |operand: &Value, value: &Option<SsaValue>| match operand {
                    Value::Const(_) => true,
                    Value::Reg(_) => value.as_ref().is_some_and(|value| offsets.contains(value)),
                    Value::Addr(_) => false,
                };
                let result_is_offset = match op {
                    BinOp::Mul | BinOp::Shl => true,
                    BinOp::Add | BinOp::Sub => {
                        is_offset(lhs, &lhs_value) && is_offset(rhs, &rhs_value)
                    }
                    _ => false,
                };
                if result_is_offset && offsets.insert(dst.clone()) {
                    grew = true;
                }
            }
        }
        if !grew {
            break;
        }
    }

    // Copies, MULTIEQUAL/phi edges, pointer arithmetic, and spill slots feed
    // each other. Iterate them as one small monotone data-flow problem.
    for _ in 0..16 {
        let mut changed = false;
        for (dst, source) in &copy_edges {
            changed |= unify_values(&mut tm, dst, source);
        }
        for phi in &ssa.phis {
            let result = SsaValue {
                base: phi.base.clone(),
                version: phi.dst_version,
            };
            if !live_phi_values.contains(&result) {
                continue;
            }
            for (_, version) in &phi.incoming {
                let incoming = SsaValue {
                    base: phi.base.clone(),
                    version: *version,
                };
                changed |= unify_values(&mut tm, &result, &incoming);
            }
        }

        for (block_idx, block) in lf.blocks.iter().enumerate() {
            for (instr_idx, ins) in block.instrs.iter().enumerate() {
                let addr = InstrAddr {
                    block_idx,
                    instr_idx,
                };
                let values = instruction_values(lf, ssa, addr);
                match &ins.op {
                    Op::Bin {
                        op: BinOp::Add,
                        lhs,
                        rhs,
                        ..
                    } => {
                        let Some((_, dst)) = &values.def else {
                            continue;
                        };
                        let Some(TypeHint::Pointer { pointee_width }) = tm.get(dst) else {
                            continue;
                        };
                        let mut cursor = 0;
                        let lhs_value = operand_value(lhs, &values, &mut cursor);
                        let rhs_value = operand_value(rhs, &values, &mut cursor);
                        let is_offset = |operand: &Value, value: &Option<SsaValue>| match operand {
                            Value::Const(_) => true,
                            Value::Reg(_) => {
                                value.as_ref().is_some_and(|value| offsets.contains(value))
                            }
                            Value::Addr(_) => false,
                        };
                        let is_reload = |value: &Option<SsaValue>| {
                            value.as_ref().is_some_and(|value| reloads.contains(value))
                        };
                        let base = if is_reload(&lhs_value) && !is_reload(&rhs_value) {
                            lhs_value
                        } else if is_reload(&rhs_value) && !is_reload(&lhs_value) {
                            rhs_value
                        } else if is_offset(rhs, &rhs_value) && !is_offset(lhs, &lhs_value) {
                            lhs_value
                        } else if is_offset(lhs, &lhs_value) && !is_offset(rhs, &rhs_value) {
                            rhs_value
                        } else {
                            None
                        };
                        if let Some(base) = base {
                            changed |= tm.upsert(base, TypeHint::Pointer { pointee_width });
                        }
                    }
                    Op::Load { addr, .. } => {
                        let Some(slot) = frame_slot(addr) else {
                            continue;
                        };
                        let Some(sources) = live_in_spills.get(&slot) else {
                            continue;
                        };
                        let Some((_, dst)) = &values.def else {
                            continue;
                        };
                        if let Some(TypeHint::Pointer { pointee_width }) = tm.get(dst) {
                            for source in sources {
                                let hint = TypeHint::Pointer { pointee_width };
                                changed |= tm.upsert(source.clone(), hint);
                                changed |= tm.upsert_parameter_refinement(source.clone(), hint);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        if !changed {
            break;
        }
    }

    // Constants demote only the definition that received the constant. They do
    // not erase an earlier pointer/code-pointer lifetime in the same storage.
    for (value, hint) in constant_defs {
        tm.inner.insert(value, hint);
    }

    tm
}

/// Produce a [`TypeMap`] for all register VRegs touched by `lf`.
pub fn recover_types(lf: &LlirFunction) -> TypeMap {
    let mut tm = TypeMap::default();

    // First pass: gather registers that ever receive a plain constant
    // assignment (`%rax = 0`, `%rdi = 42`, …). Any such register cannot be
    // a stable pointer or code-pointer — the pointer classification is
    // noise from an unrelated use-site and would produce `(fnptr)%ret = 0;`
    // style output. We'll use this to post-process the map below.
    let mut gets_const: std::collections::HashSet<VReg> = std::collections::HashSet::new();
    for block in &lf.blocks {
        for ins in &block.instrs {
            if let Op::Assign {
                dst,
                src: Value::Const(_),
            } = &ins.op
            {
                gets_const.insert(dst.clone());
            }
        }
    }

    for block in &lf.blocks {
        for ins in &block.instrs {
            // Width-from-register-name for every value register (specific
            // classifications below still win via `upsert`).
            tag_value_regs(&ins.op, &mut tm);
            match &ins.op {
                // Any register used as the base of a memory op is a pointer.
                Op::Load { addr, .. } | Op::Store { addr, .. } => {
                    if let Some(b) = &addr.base {
                        tm.upsert(
                            b.clone(),
                            TypeHint::Pointer {
                                pointee_width: addr.size.max(1),
                            },
                        );
                    }
                    if let Some(i) = &addr.index {
                        // Index registers are unsigned integers (array offsets).
                        tm.upsert(
                            i.clone(),
                            TypeHint::Int {
                                signed: false,
                                width: reg_width_bytes(i),
                            },
                        );
                    }
                }
                // A logical right shift is an unsigned operation on its value;
                // the count is unsigned for every shift family. This distinction
                // is executable semantics, not a source-style guess: widening a
                // 32-bit `shr` operand as signed changes negative inputs into a
                // 64-bit all-ones prefix and doubles the loop trip count.
                Op::Bin {
                    dst,
                    op: BinOp::Shr,
                    lhs,
                    rhs,
                } => {
                    if matches!(dst, VReg::Phys(_)) {
                        tm.upsert(
                            dst.clone(),
                            TypeHint::Int {
                                signed: false,
                                width: reg_width_bytes(dst),
                            },
                        );
                    }
                    if let Value::Reg(r) = lhs {
                        tm.upsert(
                            r.clone(),
                            TypeHint::Int {
                                signed: false,
                                width: reg_width_bytes(r),
                            },
                        );
                    }
                    if let Value::Reg(r) = rhs {
                        tm.upsert(
                            r.clone(),
                            TypeHint::Int {
                                signed: false,
                                width: reg_width_bytes(r),
                            },
                        );
                    }
                }
                // Shift counts are unsigned integers.
                Op::Bin {
                    op: BinOp::Shl | BinOp::Sar,
                    rhs,
                    ..
                } => {
                    if let Value::Reg(r) = rhs {
                        tm.upsert(
                            r.clone(),
                            TypeHint::Int {
                                signed: false,
                                width: reg_width_bytes(r),
                            },
                        );
                    }
                }
                // Indirect call target → code pointer.
                Op::Call {
                    target: crate::ir::types::CallTarget::Indirect(Value::Reg(r)),
                    ..
                } => {
                    tm.upsert(r.clone(), TypeHint::CodePointer);
                }
                // Default: arithmetic-producing binops leave the result a
                // generic signed 8-byte int unless something more specific
                // promotes it later.
                Op::Bin { dst, .. } => {
                    if let VReg::Phys(_) = dst {
                        tm.upsert(dst.clone(), classify_int_default());
                    }
                }
                _ => {}
            }
        }
    }

    // Propagate pointer-ness from a stack slot back to the register spilled
    // into it. At `-O0` a pointer *argument* is spilled to a frame slot
    // (`store [rbp-8] = rdi`) in the prologue and every later dereference goes
    // through a *reload* of that slot into a scratch register — so the pointer
    // classification lands on the reloaded temp, never on the incoming argument
    // register. Link them: `reg -> slot` (the spill) and `slot -> pointer`
    // (a reload of that slot that is itself a pointer), then tag the spilled
    // register as the pointer. This is what recovers `T *` argument types.
    // Address arithmetic first (`p = base + i` with `*p` -> `base` is a pointer),
    // then spill-slot propagation (a slot reloaded into a pointer is a pointer,
    // and so is the argument spilled into it) — so a pointer parameter used as
    // `*(param + i*scale)` resolves through the reload to the parameter. Iterated
    // together so either order of discovery converges.
    for _ in 0..4 {
        propagate_pointer_arithmetic(lf, &mut tm);
        propagate_spill_slot_pointers(lf, &mut tm);
    }

    // Demote pointer / code-pointer classifications for regs that get a
    // constant assignment. They end up as generic ints — which the printer
    // leaves uncluttered.
    let to_demote: Vec<VReg> = tm
        .inner
        .iter()
        .filter(|(k, v)| {
            gets_const.contains(k) && matches!(v, TypeHint::Pointer { .. } | TypeHint::CodePointer)
        })
        .map(|(k, _)| k.clone())
        .collect();
    for k in to_demote {
        let hint = int_for_reg(&k);
        tm.inner.insert(k, hint);
    }

    tm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ssa::{compute_ssa, SsaValue};
    use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg, Value};

    fn mk_block(ops: Vec<Op>) -> LlirFunction {
        LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1100,
                instrs: ops
                    .into_iter()
                    .enumerate()
                    .map(|(j, op)| LlirInstr {
                        va: 0x1000 + (j as u64) * 4,
                        op,
                    })
                    .collect(),
                succs: vec![],
            }],
        }
    }

    #[test]
    fn load_base_tagged_pointer() {
        let lf = mk_block(vec![Op::Load {
            dst: VReg::phys("rax"),
            addr: MemOp {
                base: Some(VReg::phys("rbp")),
                index: None,
                scale: 0,
                disp: -8,
                size: 8,
                ..Default::default()
            },
        }]);
        let tm = recover_types(&lf);
        assert_eq!(
            tm.get(&VReg::phys("rbp")),
            Some(TypeHint::Pointer { pointee_width: 8 })
        );
    }

    #[test]
    fn explicit_zero_extension_recovers_source_and_result_widths() {
        let lf = mk_block(vec![Op::ZExt {
            dst: VReg::phys("eax"),
            src: Value::Reg(VReg::phys("edi")),
            from: crate::ir::types::Width::W32,
            to: crate::ir::types::Width::W64,
        }]);

        let tm = recover_types(&lf);

        assert_eq!(
            tm.get(&VReg::phys("edi")),
            Some(TypeHint::Int {
                signed: true,
                width: 4,
            })
        );
        assert_eq!(
            tm.get(&VReg::phys("eax")),
            Some(TypeHint::Int {
                signed: false,
                width: 8,
            })
        );
    }

    #[test]
    fn value_refinement_preserves_richer_scalar_signedness_but_fixes_class() {
        let role = VReg::phys("arg0");
        let mut tm = TypeMap::default();
        tm.upsert_public(
            role.clone(),
            TypeHint::Int {
                signed: false,
                width: 4,
            },
        );
        tm.refine_from_value(
            role.clone(),
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );
        assert_eq!(
            tm.get(&role),
            Some(TypeHint::Int {
                signed: false,
                width: 4,
            }),
            "value identity must not discard stronger operation-level signedness"
        );

        tm.refine_from_value(role.clone(), TypeHint::Pointer { pointee_width: 1 });
        assert_eq!(
            tm.get(&role),
            Some(TypeHint::Pointer { pointee_width: 1 }),
            "value identity must correct a scalar/address class collision"
        );
    }

    #[test]
    fn spilled_pointer_arg_recovered_through_address_add() {
        use crate::ir::types::BinOp;
        // The `-O0` array-index idiom, post value-numbering:
        //   store [rbp-24] = rdi      ; spill the pointer argument
        //   rdx = rcx * 4             ; scaled index (an offset register)
        //   rax = [rbp-24]            ; reload the spilled pointer
        //   r8  = rax + rdx           ; base + index  (the address)
        //   r9  = *r8                 ; dereference   -> r8 is a pointer
        // Nothing dereferences rdi directly, so the pointer type on the argument
        // can only be recovered by: r8 pointer -> rax (the reload) is the base ->
        // the spill slot -> rdi. Regression guard for that whole chain.
        let lf = mk_block(vec![
            Op::Store {
                addr: MemOp {
                    base: Some(VReg::phys("rbp")),
                    index: None,
                    scale: 1,
                    disp: -24,
                    size: 8,
                    ..Default::default()
                },
                src: Value::Reg(VReg::phys("rdi")),
            },
            Op::Bin {
                op: BinOp::Mul,
                dst: VReg::phys("rdx"),
                lhs: Value::Reg(VReg::phys("rcx")),
                rhs: Value::Const(4),
            },
            Op::Load {
                dst: VReg::phys("rax"),
                addr: MemOp {
                    base: Some(VReg::phys("rbp")),
                    index: None,
                    scale: 1,
                    disp: -24,
                    size: 8,
                    ..Default::default()
                },
            },
            Op::Bin {
                op: BinOp::Add,
                dst: VReg::phys("r8"),
                lhs: Value::Reg(VReg::phys("rax")),
                rhs: Value::Reg(VReg::phys("rdx")),
            },
            Op::Load {
                dst: VReg::phys("r9"),
                addr: MemOp {
                    base: Some(VReg::phys("r8")),
                    index: None,
                    scale: 1,
                    disp: 0,
                    size: 4,
                    ..Default::default()
                },
            },
        ]);
        let tm = recover_types(&lf);
        assert!(
            matches!(tm.get(&VReg::phys("rdi")), Some(TypeHint::Pointer { .. })),
            "spilled pointer argument rdi should be recovered as a pointer, got {:?}",
            tm.get(&VReg::phys("rdi"))
        );
        // The scaled index must NOT be mistaken for a pointer.
        assert!(
            !matches!(tm.get(&VReg::phys("rdx")), Some(TypeHint::Pointer { .. })),
            "scaled index rdx must not be typed as a pointer"
        );
    }

    #[test]
    fn valued_recovery_does_not_demote_an_earlier_pointer_definition() {
        // One architectural register, two unrelated values:
        //   rdi#0 is the incoming pointer and is dereferenced;
        //   rdi#1 is a later scalar constant.
        // Flow-insensitive recovery demotes the entire register because it sees
        // the constant. Value-keyed recovery must keep the two facts separate.
        let lf = mk_block(vec![
            Op::Load {
                dst: VReg::phys("eax"),
                addr: MemOp {
                    base: Some(VReg::phys("rdi")),
                    index: None,
                    scale: 1,
                    disp: 0,
                    size: 4,
                    ..Default::default()
                },
            },
            Op::Assign {
                dst: VReg::phys("edi"),
                src: Value::Const(0),
            },
        ]);
        let ssa = compute_ssa(&lf);
        let tm = recover_types_valued(&lf, &ssa);
        let incoming = SsaValue {
            base: VReg::phys("rdi"),
            version: 0,
        };
        let scalar = ssa
            .def_value(
                &lf,
                crate::ir::use_def::InstrAddr {
                    block_idx: 0,
                    instr_idx: 1,
                },
            )
            .expect("constant definition value");

        assert_eq!(
            tm.get(&incoming),
            Some(TypeHint::Pointer { pointee_width: 4 })
        );
        assert!(matches!(
            tm.get(&scalar),
            Some(TypeHint::Int { width: 4, .. })
        ));
    }

    #[test]
    fn dead_phi_does_not_merge_live_in_scalar_with_later_pointer_reuse() {
        let block = |start_va: u64, ops: Vec<Op>, succs: Vec<u64>| LlirBlock {
            start_va,
            end_va: start_va + 0x10,
            instrs: ops
                .into_iter()
                .enumerate()
                .map(|(index, op)| LlirInstr {
                    va: start_va + index as u64 * 4,
                    op,
                })
                .collect(),
            succs,
        };
        // rsi#0 is an integer parameter. Only one branch later reuses rsi as a
        // pointer, and the merge-point phi is dead: nothing reads its result.
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                block(
                    0x1000,
                    vec![Op::CondJump {
                        cond: VReg::phys("rsi"),
                        target: 0x1020,
                        inverted: false,
                    }],
                    vec![0x1010, 0x1020],
                ),
                block(
                    0x1010,
                    vec![
                        Op::Assign {
                            dst: VReg::phys("rsi"),
                            src: Value::Reg(VReg::phys("rdi")),
                        },
                        Op::Load {
                            dst: VReg::phys("eax"),
                            addr: MemOp {
                                base: Some(VReg::phys("rsi")),
                                index: None,
                                scale: 1,
                                disp: 0,
                                size: 4,
                                ..Default::default()
                            },
                        },
                    ],
                    vec![0x1030],
                ),
                block(0x1020, vec![Op::Nop], vec![0x1030]),
                block(0x1030, vec![Op::Return], vec![]),
            ],
        };
        let ssa = compute_ssa(&lf);
        assert!(
            ssa.phis.iter().any(|phi| phi.base == VReg::phys("rsi")),
            "fixture must contain the dead merge phi"
        );
        let tm = recover_types_valued(&lf, &ssa);
        assert_eq!(
            tm.get(&SsaValue {
                base: VReg::phys("rsi"),
                version: 0,
            }),
            Some(TypeHint::Int {
                signed: true,
                width: 8,
            })
        );
    }

    #[test]
    fn real_gcc_o2_loop_propagates_pointer_type_to_live_in_value() {
        use object::{Object, ObjectSymbol};
        use std::io::Write;
        use std::process::Command;

        let tmp = tempfile::tempdir().expect("temporary memory fixture build directory");
        let source = tmp.path().join("09_memory_effects.c");
        let binary = tmp.path().join("09_memory_effects.so");
        std::fs::File::create(&source)
            .and_then(|mut file| {
                file.write_all(include_bytes!(
                    "../../tests/decompiler_fixtures/src/09_memory_effects.c"
                ))
            })
            .expect("write the real memory-effects fixture source");
        let build = match Command::new("gcc")
            .args(["-shared", "-fPIC", "-g", "-O2", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()
        {
            Ok(build) => build,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => panic!("launch GCC: {error}"),
        };
        assert!(
            build.status.success(),
            "compile the real memory-effects fixture with GCC -O2: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let data = std::fs::read(&binary).expect("read GCC output");
        let object = object::read::File::parse(data.as_slice()).expect("parse GCC ELF");
        let entry = object
            .dynamic_symbols()
            .find(|symbol| symbol.name().ok() == Some("vec_sum"))
            .map(|symbol| symbol.address())
            .expect("exported vec_sum symbol");
        let (functions, _) = crate::analysis::cfg::analyze_functions_bytes(
            &data,
            &crate::analysis::cfg::Budgets::default(),
        );
        let function = functions
            .iter()
            .find(|function| function.entry_point.value == entry)
            .expect("discovered vec_sum function");
        let lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            function,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift vec_sum");
        let ssa = compute_ssa(&lifted);
        let tm = recover_types_valued(&lifted, &ssa);

        assert_eq!(
            tm.get(&SsaValue {
                base: VReg::phys("rdi"),
                version: 0,
            }),
            Some(TypeHint::Pointer { pointee_width: 4 }),
            "the loop-carried dereference must flow through its phi and pointer increment to arg0"
        );
    }

    #[test]
    fn real_gcc_o0_spills_propagate_both_string_pointer_live_ins() {
        use object::{Object, ObjectSymbol};
        use std::io::Write;
        use std::process::Command;

        let tmp = tempfile::tempdir().expect("temporary string fixture build directory");
        let source = tmp.path().join("strops.c");
        let binary = tmp.path().join("strops.so");
        std::fs::File::create(&source)
            .and_then(|mut file| {
                file.write_all(include_bytes!("../../tests/decbench_corpus/src/strops.c"))
            })
            .expect("write the real DecBench string fixture source");
        let build = match Command::new("gcc")
            .args(["-shared", "-fPIC", "-g", "-O0", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()
        {
            Ok(build) => build,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => panic!("launch GCC: {error}"),
        };
        assert!(
            build.status.success(),
            "compile the real DecBench string fixture with GCC -O0: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let data = std::fs::read(&binary).expect("read GCC output");
        let object = object::read::File::parse(data.as_slice()).expect("parse GCC ELF");
        let entry = object
            .dynamic_symbols()
            .find(|symbol| symbol.name().ok() == Some("str_cmp"))
            .map(|symbol| symbol.address())
            .expect("exported str_cmp symbol");
        let (functions, _) = crate::analysis::cfg::analyze_functions_bytes(
            &data,
            &crate::analysis::cfg::Budgets::default(),
        );
        let function = functions
            .iter()
            .find(|function| function.entry_point.value == entry)
            .expect("discovered str_cmp function");
        let lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            function,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift str_cmp");
        let ssa = compute_ssa(&lifted);
        let tm = recover_types_valued(&lifted, &ssa);
        let refinements = tm.parameter_refinements();

        for register in ["rdi", "rsi"] {
            assert_eq!(
                tm.get(&SsaValue {
                    base: VReg::phys(register),
                    version: 0,
                }),
                Some(TypeHint::Pointer { pointee_width: 1 }),
                "{register} must retain its caller-supplied string-pointer type through the spill"
            );
            assert_eq!(
                refinements.get(&VReg::phys(register)),
                Some(TypeHint::Pointer { pointee_width: 1 }),
                "{register} has the spill/reload/dereference proof required to refine a rendered parameter"
            );
        }
    }

    #[test]
    fn direct_live_in_fact_is_not_yet_a_rendered_parameter_refinement() {
        // A direct memory use proves that this SSA value is address-bearing,
        // but it is not enough to rewrite the source prototype while function
        // boundaries and recovered callees are still incomplete. The first
        // output-facing slice deliberately accepts only the stronger O0
        // spill/reload/dereference chain exercised above.
        let lf = mk_block(vec![Op::Load {
            dst: VReg::phys("eax"),
            addr: MemOp {
                base: Some(VReg::phys("rdi")),
                index: None,
                scale: 1,
                disp: 0,
                size: 4,
                ..Default::default()
            },
        }]);
        let ssa = compute_ssa(&lf);
        let tm = recover_types_valued(&lf, &ssa);

        assert_eq!(
            tm.get(&SsaValue {
                base: VReg::phys("rdi"),
                version: 0,
            }),
            Some(TypeHint::Pointer { pointee_width: 4 })
        );
        assert!(
            tm.parameter_refinements().is_empty(),
            "unqualified live-in facts must remain analysis evidence, not rendered prototype facts"
        );
    }

    #[test]
    fn lone_spilled_pointer_fact_is_not_yet_a_rendered_parameter_refinement() {
        // A single address-taken scalar can have this same machine shape after
        // optimization: spill one incoming value, reload it, then let an
        // over-discovered tail use the reload as an address. Requiring a second
        // independently qualified entry value keeps that case from rewriting
        // the public prototype until prototype recovery and function bounds are
        // authoritative.
        let lf = mk_block(vec![
            Op::Store {
                addr: MemOp {
                    base: Some(VReg::phys("rbp")),
                    index: None,
                    scale: 1,
                    disp: -8,
                    size: 8,
                    ..Default::default()
                },
                src: Value::Reg(VReg::phys("rdi")),
            },
            Op::Load {
                dst: VReg::phys("rax"),
                addr: MemOp {
                    base: Some(VReg::phys("rbp")),
                    index: None,
                    scale: 1,
                    disp: -8,
                    size: 8,
                    ..Default::default()
                },
            },
            Op::Load {
                dst: VReg::phys("ecx"),
                addr: MemOp {
                    base: Some(VReg::phys("rax")),
                    index: None,
                    scale: 1,
                    disp: 0,
                    size: 4,
                    ..Default::default()
                },
            },
        ]);
        let ssa = compute_ssa(&lf);
        let tm = recover_types_valued(&lf, &ssa);

        assert_eq!(
            tm.get(&SsaValue {
                base: VReg::phys("rdi"),
                version: 0,
            }),
            Some(TypeHint::Pointer { pointee_width: 4 })
        );
        assert!(
            tm.parameter_refinements().is_empty(),
            "one qualified live-in is not enough to rewrite a rendered prototype"
        );
    }

    #[test]
    fn wider_pointee_overwrites_narrower() {
        // First use: u8 pointer. Second use: u64 pointer. Result: 8.
        let lf = mk_block(vec![
            Op::Load {
                dst: VReg::phys("rax"),
                addr: MemOp {
                    base: Some(VReg::phys("rbx")),
                    index: None,
                    scale: 0,
                    disp: 0,
                    size: 1,
                    ..Default::default()
                },
            },
            Op::Load {
                dst: VReg::phys("rax"),
                addr: MemOp {
                    base: Some(VReg::phys("rbx")),
                    index: None,
                    scale: 0,
                    disp: 0,
                    size: 8,
                    ..Default::default()
                },
            },
        ]);
        let tm = recover_types(&lf);
        assert_eq!(
            tm.get(&VReg::phys("rbx")),
            Some(TypeHint::Pointer { pointee_width: 8 })
        );
    }

    #[test]
    fn return_type_narrowed_from_last_definition() {
        use crate::ir::call_args::CallConv;
        use crate::ir::types::BinOp;
        // rax is used as a pointer base (spurious for the return), but the LAST
        // write to the return register is a 32-bit multiply into eax -> the
        // function returns an int, not a pointer.
        let lf = mk_block(vec![
            Op::Load {
                dst: VReg::phys("rcx"),
                addr: MemOp {
                    base: Some(VReg::phys("rax")),
                    index: None,
                    scale: 0,
                    disp: 0,
                    size: 4,
                    ..Default::default()
                },
            },
            Op::Bin {
                dst: VReg::phys("eax"),
                op: BinOp::Mul,
                lhs: Value::Reg(VReg::phys("eax")),
                rhs: Value::Reg(VReg::phys("ecx")),
            },
        ]);
        // Bare recover_types leaves rax as a pointer (union of all uses).
        let raw = recover_types(&lf);
        assert!(matches!(
            raw.get(&VReg::phys("rax")),
            Some(TypeHint::Pointer { .. })
        ));
        // The cc-aware entry corrects it: last def is a 32-bit write to eax.
        let tm = recover_types_for(&lf, CallConv::SysVAmd64);
        assert_eq!(
            tm.get(&VReg::phys("rax")),
            Some(TypeHint::Int {
                signed: true,
                width: 4
            }),
            "return should be narrowed to int from the 32-bit last def"
        );
    }

    #[test]
    fn pointer_return_via_full_width_is_preserved() {
        use crate::ir::call_args::CallConv;
        // Last def writes the full 64-bit rax by loading a pointer slot -> a
        // genuine pointer return must survive the refinement.
        let lf = mk_block(vec![Op::Load {
            dst: VReg::phys("rax"),
            addr: MemOp {
                base: Some(VReg::phys("rbp")),
                index: None,
                scale: 0,
                disp: -8,
                size: 8,
                ..Default::default()
            },
        }]);
        // Make rax a pointer via a subsequent deref so the union sees a pointer.
        let mut lf = lf;
        lf.blocks[0].instrs.push(LlirInstr {
            va: 0x2000,
            op: Op::Load {
                dst: VReg::phys("rdx"),
                addr: MemOp {
                    base: Some(VReg::phys("rax")),
                    index: None,
                    scale: 0,
                    disp: 0,
                    size: 8,
                    ..Default::default()
                },
            },
        });
        let tm = recover_types_for(&lf, CallConv::SysVAmd64);
        assert!(
            matches!(tm.get(&VReg::phys("rax")), Some(TypeHint::Pointer { .. })),
            "full-width pointer return must be preserved, got {:?}",
            tm.get(&VReg::phys("rax"))
        );
    }

    #[test]
    fn pointer_arg_recovered_through_spill_slot() {
        // -O0 pattern: rdi (arg0) is spilled to [rbp-8], later reloaded into
        // rax which is dereferenced. rax is a pointer; the propagation must
        // push that back onto rdi so the argument types as a pointer.
        let lf = mk_block(vec![
            Op::Store {
                addr: MemOp {
                    base: Some(VReg::phys("rbp")),
                    index: None,
                    scale: 0,
                    disp: -8,
                    size: 8,
                    ..Default::default()
                },
                src: Value::Reg(VReg::phys("rdi")),
            },
            Op::Load {
                dst: VReg::phys("rax"),
                addr: MemOp {
                    base: Some(VReg::phys("rbp")),
                    index: None,
                    scale: 0,
                    disp: -8,
                    size: 8,
                    ..Default::default()
                },
            },
            Op::Load {
                dst: VReg::phys("rcx"),
                addr: MemOp {
                    base: Some(VReg::phys("rax")),
                    index: None,
                    scale: 0,
                    disp: 0,
                    size: 4,
                    ..Default::default()
                },
            },
        ]);
        let tm = recover_types(&lf);
        assert!(
            matches!(tm.get(&VReg::phys("rdi")), Some(TypeHint::Pointer { .. })),
            "arg spilled to slot then dereferenced should type as pointer, got {:?}",
            tm.get(&VReg::phys("rdi"))
        );
    }

    #[test]
    fn index_tagged_unsigned_int() {
        let lf = mk_block(vec![Op::Load {
            dst: VReg::phys("rax"),
            addr: MemOp {
                base: Some(VReg::phys("rdi")),
                index: Some(VReg::phys("rcx")),
                scale: 4,
                disp: 0,
                size: 4,
                ..Default::default()
            },
        }]);
        let tm = recover_types(&lf);
        assert!(matches!(
            tm.get(&VReg::phys("rcx")),
            Some(TypeHint::Int { signed: false, .. })
        ));
    }

    #[test]
    fn cmp_eq_zero_does_not_retype_an_integer_as_bool() {
        use crate::ir::types::{CmpOp, Flag};
        let lf = mk_block(vec![Op::Cmp {
            dst: VReg::Flag(Flag::Z),
            op: CmpOp::Eq,
            lhs: Value::Reg(VReg::phys("rax")),
            rhs: Value::Const(0),
        }]);
        let tm = recover_types(&lf);
        assert_eq!(
            tm.get(&VReg::phys("rax")),
            Some(TypeHint::Int {
                signed: true,
                width: 8,
            })
        );
    }

    #[test]
    fn indirect_call_target_is_code_pointer() {
        use crate::ir::types::CallTarget;
        let lf = mk_block(vec![Op::Call {
            target: CallTarget::Indirect(Value::Reg(VReg::phys("rax"))),
            effects: None,
        }]);
        let tm = recover_types(&lf);
        assert_eq!(tm.get(&VReg::phys("rax")), Some(TypeHint::CodePointer));
    }

    #[test]
    fn shift_count_tagged_unsigned() {
        use crate::ir::types::BinOp;
        let lf = mk_block(vec![Op::Bin {
            dst: VReg::phys("rax"),
            op: BinOp::Shl,
            lhs: Value::Reg(VReg::phys("rax")),
            rhs: Value::Reg(VReg::phys("rcx")),
        }]);
        let tm = recover_types(&lf);
        assert!(matches!(
            tm.get(&VReg::phys("rcx")),
            Some(TypeHint::Int { signed: false, .. })
        ));
    }

    #[test]
    fn logical_right_shift_tags_the_shifted_value_unsigned() {
        let lf = mk_block(vec![Op::Bin {
            dst: VReg::phys("edi"),
            op: BinOp::Shr,
            lhs: Value::Reg(VReg::phys("edi")),
            rhs: Value::Const(1),
        }]);
        let tm = recover_types(&lf);
        assert_eq!(
            tm.get(&VReg::phys("edi")),
            Some(TypeHint::Int {
                signed: false,
                width: 4,
            })
        );
    }

    #[test]
    fn pointer_beats_int_promotion_order() {
        // First: rbx used as arithmetic result (int). Second: rbx used as
        // pointer base. Final type must be pointer.
        use crate::ir::types::BinOp;
        let lf = mk_block(vec![
            Op::Bin {
                dst: VReg::phys("rbx"),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::phys("rbx")),
                rhs: Value::Const(1),
            },
            Op::Load {
                dst: VReg::phys("rax"),
                addr: MemOp {
                    base: Some(VReg::phys("rbx")),
                    index: None,
                    scale: 0,
                    disp: 0,
                    size: 4,
                    ..Default::default()
                },
            },
        ]);
        let tm = recover_types(&lf);
        assert!(matches!(
            tm.get(&VReg::phys("rbx")),
            Some(TypeHint::Pointer { .. })
        ));
    }

    #[test]
    fn const_assignment_demotes_pointer_classification() {
        // `%rax = load [rax+0]; %rax = 0;` — the load marks %rax as pointer
        // (actually rax is the *dst*, but let's instead use a different
        // reg as a base). Here the scenario is: `rbp` is used as a pointer
        // base in a load, then gets a constant assignment. The constant
        // assignment should demote it.
        use crate::ir::types::{BinOp, LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg, Value};
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1100,
                instrs: vec![
                    LlirInstr {
                        va: 0x1000,
                        op: Op::Load {
                            dst: VReg::phys("rax"),
                            addr: MemOp {
                                base: Some(VReg::phys("rbp")),
                                index: None,
                                scale: 0,
                                disp: 0,
                                size: 8,
                                ..Default::default()
                            },
                        },
                    },
                    LlirInstr {
                        va: 0x1004,
                        op: Op::Assign {
                            dst: VReg::phys("rbp"),
                            src: Value::Const(0),
                        },
                    },
                ],
                succs: vec![],
            }],
        };
        let tm = recover_types(&lf);
        // rbp was seen as a pointer base AND as the target of a const
        // assignment — must be demoted to Int.
        match tm.get(&VReg::phys("rbp")) {
            Some(TypeHint::Int { .. }) | None => {}
            other => panic!("expected Int for demoted rbp; got {:?}", other),
        }
        // Keep the suppress-unused ref to BinOp away from warnings.
        let _ = BinOp::Add;
    }

    #[test]
    fn real_binary_produces_non_empty_type_map() {
        use crate::analysis::cfg::{analyze_functions_bytes, Budgets};
        use crate::core::binary::Arch;
        use crate::ir::lift_function::lift_function_from_bytes;
        let path = std::path::Path::new(
            "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2",
        );
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let (funcs, _) = analyze_functions_bytes(
            &data,
            &Budgets {
                max_functions: 4,
                max_blocks: 128,
                max_instructions: 2000,
                timeout_ms: 500,
            },
        );
        let mut saw_pointer = false;
        for f in &funcs {
            if let Some(lf) = lift_function_from_bytes(&data, f, Arch::X86_64) {
                let tm = recover_types(&lf);
                if tm
                    .iter()
                    .any(|(_, t)| matches!(t, TypeHint::Pointer { .. }))
                {
                    saw_pointer = true;
                }
            }
        }
        assert!(
            saw_pointer,
            "expected at least one pointer classification across discovered functions"
        );
    }
}
