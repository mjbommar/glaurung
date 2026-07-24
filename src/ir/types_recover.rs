//! First-cut type recovery for VRegs in an [`LlirFunction`].
//!
//! v0 scope — deliberately tiny, but useful:
//!
//! * Registers used as the base of a `Load`/`Store` memory operand are
//!   classified as **pointers**. The inferred pointee width comes from the
//!   memory access size.
//! * Registers compared against zero with `CmpOp::Eq` are tagged
//!   **boolean-ish** (likely hold a truth value).
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

use std::collections::HashMap;

use crate::ir::types::{BinOp, CmpOp, LlirFunction, Op, VReg, Value};

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

    /// Union-style update: only overwrite when `new` is strictly more
    /// specific than the current entry. Pointers beat ints; specific widths
    /// beat zero-width entries; bool beats nothing.
    fn upsert(&mut self, reg: VReg, new: TypeHint) {
        let cur = self.inner.get(&reg).copied();
        let keep = match (cur, new) {
            (None, _) => new,
            // Pointer / CodePointer are the strongest (semantic) classifications
            // and win over a plain integer or bool.
            (
                Some(TypeHint::Int { .. }) | Some(TypeHint::BoolLike),
                TypeHint::Pointer { .. } | TypeHint::CodePointer,
            ) => new,
            // Wider pointee replaces narrower pointee.
            (
                Some(TypeHint::Pointer { pointee_width: a }),
                TypeHint::Pointer { pointee_width: b },
            ) if b > a => new,
            // Nothing downgrades an established pointer / code-pointer.
            (Some(TypeHint::Pointer { .. }) | Some(TypeHint::CodePointer), _) => cur.unwrap(),
            // A value only ever tested against zero is bool-ish; that beats a
            // plain integer, but an integer signal never overwrites it.
            (Some(TypeHint::Int { .. }), TypeHint::BoolLike) => new,
            (Some(TypeHint::BoolLike), TypeHint::Int { .. }) => cur.unwrap(),
            (Some(TypeHint::BoolLike), TypeHint::BoolLike) => new,
            // Int + Int: unsigned is sticky (we only ever *assert* unsigned, from
            // shifts / index / movzx; signed is the silent default), and we keep
            // the more-specific (narrower, register-sub-name-derived) width over
            // the conservative 8-byte fallback.
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
        };
        self.inner.insert(reg, keep);
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
    let mut tag = |val: &Value, tm: &mut TypeMap| {
        if let Value::Reg(r @ VReg::Phys(_)) = val {
            tm.upsert(r.clone(), int_for_reg(r));
        }
    };
    match op {
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
                        BinOp::Add | BinOp::Sub => {
                            is_off(&offsets, lhs) && is_off(&offsets, rhs)
                        }
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
                // Shift counts are unsigned integers.
                Op::Bin {
                    op: BinOp::Shl | BinOp::Shr | BinOp::Sar,
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
                // Compared against zero → likely boolean.
                Op::Cmp {
                    op: CmpOp::Eq,
                    lhs: Value::Reg(r),
                    rhs: Value::Const(0),
                    ..
                }
                | Op::Cmp {
                    op: CmpOp::Eq,
                    lhs: Value::Const(0),
                    rhs: Value::Reg(r),
                    ..
                } => {
                    tm.upsert(r.clone(), TypeHint::BoolLike);
                }
                // Indirect call target → code pointer.
                Op::Call {
                    target: crate::ir::types::CallTarget::Indirect(Value::Reg(r)),
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
    fn cmp_eq_zero_marks_bool() {
        use crate::ir::types::{CmpOp, Flag};
        let lf = mk_block(vec![Op::Cmp {
            dst: VReg::Flag(Flag::Z),
            op: CmpOp::Eq,
            lhs: Value::Reg(VReg::phys("rax")),
            rhs: Value::Const(0),
        }]);
        let tm = recover_types(&lf);
        assert_eq!(tm.get(&VReg::phys("rax")), Some(TypeHint::BoolLike));
    }

    #[test]
    fn indirect_call_target_is_code_pointer() {
        use crate::ir::types::CallTarget;
        let lf = mk_block(vec![Op::Call {
            target: CallTarget::Indirect(Value::Reg(VReg::phys("rax"))),
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
