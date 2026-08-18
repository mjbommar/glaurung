//! The value-hint lattice and the register-tagging pass.
//!
//! [`merge_type_hint`] is the lattice join every `upsert` in the parent runs
//! through: it decides which of two candidate [`TypeHint`](super::TypeHint)s
//! survives. Around it sit the tagging passes that produce the raw-register
//! [`TypeMap`](super::TypeMap) — [`tag_value_regs`] gives every value-carrying
//! physical register a width-appropriate default, and
//! [`propagate_spill_slot_pointers`] / [`propagate_pointer_arithmetic`] are the
//! two fixpoints that push pointer-ness across frame slots and address
//! arithmetic. [`recover_types_for`] is the production entry point that runs
//! the parent's [`recover_types`](super::recover_types) and then applies the
//! calling-convention-aware return refinement; it keeps its old
//! `crate::ir::types_recover::` path via the `pub use` re-export in the parent.
//!
//! The width vocabulary this pass shares with the value-keyed pass —
//! `reg_width_bytes` and `int_for_reg` — stays in the parent module, as
//! [`valued`](super::valued) documents.

use std::collections::HashMap;

use crate::ir::types::{BinOp, LlirFunction, Op, VReg, Value};

use super::{
    int_for_reg, recover_types, reg_width_bytes, scalar_float_intrinsic_width, scalar_vfp_register,
    TypeHint, TypeMap,
};

pub(super) fn merge_type_hint(current: Option<TypeHint>, new: TypeHint) -> TypeHint {
    match (current, new) {
        (None, _) => new,
        // Pointer / CodePointer are the strongest semantic classifications.
        (
            Some(TypeHint::Int { .. }) | Some(TypeHint::Float { .. }) | Some(TypeHint::BoolLike),
            TypeHint::Pointer { .. } | TypeHint::CodePointer,
        ) => new,
        (Some(TypeHint::Pointer { pointee_width: a }), TypeHint::Pointer { pointee_width: b })
            if b > a =>
        {
            new
        }
        (Some(TypeHint::Pointer { .. }) | Some(TypeHint::CodePointer), _) => current.unwrap(),
        (Some(TypeHint::Int { .. }) | Some(TypeHint::BoolLike), TypeHint::Float { .. }) => new,
        (Some(TypeHint::Float { .. }), TypeHint::Int { .. } | TypeHint::BoolLike) => {
            current.unwrap()
        }
        (
            Some(TypeHint::Float {
                width: current_width,
            }),
            TypeHint::Float { width: new_width },
        ) => TypeHint::Float {
            width: current_width.max(new_width),
        },
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

pub(super) fn classify_int_default() -> TypeHint {
    TypeHint::Int {
        signed: true,
        width: 8,
    }
}

fn value_hint_for_reg(v: &VReg) -> TypeHint {
    match v {
        VReg::Phys(name)
            if name
                .strip_prefix('s')
                .is_some_and(|index| index.parse::<u8>().is_ok()) =>
        {
            TypeHint::Float { width: 4 }
        }
        VReg::Phys(name)
            if name
                .strip_prefix('d')
                .is_some_and(|index| index.parse::<u8>().is_ok()) =>
        {
            TypeHint::Float { width: 8 }
        }
        _ => int_for_reg(v),
    }
}

/// Tag every physical register that carries a value in `op` with a
/// width-appropriate signed-int hint. The `upsert` policy keeps a more-specific
/// classification (pointer / bool / code-pointer / narrower width), so this only
/// fills in the width for registers nothing else has typed.
pub(super) fn tag_value_regs(op: &Op, tm: &mut TypeMap) {
    let tag = |val: &Value, tm: &mut TypeMap| {
        if let Value::Reg(r @ VReg::Phys(_)) = val {
            tm.upsert(r.clone(), value_hint_for_reg(r));
        }
    };
    let bytes = |width: crate::ir::types::Width| width.bytes().min(u8::MAX as u16) as u8;
    match op {
        // Jumps through a computed value; the target is an address, and the
        // width hint this pass applies would be wrong for one.
        Op::IndirectJump { .. } => {}
        Op::Assign { dst, src } => {
            if let VReg::Phys(_) = dst {
                tm.upsert(dst.clone(), value_hint_for_reg(dst));
            }
            tag(src, tm);
        }
        Op::Store { src, .. } => tag(src, tm),
        Op::Load { dst, .. } | Op::CondLoad { dst, .. } => {
            if let VReg::Phys(_) = dst {
                tm.upsert(dst.clone(), value_hint_for_reg(dst));
            }
        }
        Op::Bin { dst, lhs, rhs, .. } => {
            if let VReg::Phys(_) = dst {
                tm.upsert(dst.clone(), value_hint_for_reg(dst));
            }
            tag(lhs, tm);
            tag(rhs, tm);
        }
        Op::Un { dst, src, .. } => {
            if let VReg::Phys(_) = dst {
                tm.upsert(dst.clone(), value_hint_for_reg(dst));
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
        Op::Intrinsic {
            name, ins, outs, ..
        } => {
            if let Some(width) = scalar_float_intrinsic_width(name, ins, outs) {
                let hint = TypeHint::Float { width };
                for value in ins {
                    if let Value::Reg(register @ VReg::Phys(_)) = value {
                        if name != "vmov" || scalar_vfp_register(register) {
                            tm.upsert(register.clone(), hint);
                        }
                    }
                }
                for (register, _) in outs {
                    if matches!(register, VReg::Phys(_))
                        && (name != "vmov" || scalar_vfp_register(register))
                    {
                        tm.upsert(register.clone(), hint);
                    }
                }
            }
        }
        _ => {}
    }
}

/// True for a frame-relative base register (`rbp`/`rsp` on x86-64,
/// `x29`/`sp`/`w29` on AArch64) — the anchors `-O0` code spills locals against.
pub(super) fn is_frame_base(v: &VReg) -> bool {
    let VReg::Phys(name) = v else {
        return false;
    };
    let base = name.split_once('#').map_or(name.as_str(), |(base, _)| base);
    matches!(
        base,
        "rbp" | "rsp" | "ebp" | "esp" | "x29" | "sp" | "w29" | "r7" | "r11" | "fp"
    )
}

/// See the call site in [`recover_types`]. Two forward passes over `lf`:
///   1. record `slot -> register` for each spill store `[frame+disp] = reg`;
///   2. for each reload `reg = [frame+disp]` whose destination is already a
///      pointer in `tm`, propagate that pointer back to the spilled register.
pub(super) fn propagate_spill_slot_pointers(lf: &LlirFunction, tm: &mut TypeMap) {
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
pub(super) fn return_reg_names(cc: crate::ir::call_args::CallConv) -> &'static [&'static str] {
    crate::ir::abi::integer_return_registers(cc)
}

/// Dedicated floating-point result storage under `cc`, widest aliases first.
pub(super) fn float_return_reg_names(
    cc: crate::ir::call_args::CallConv,
) -> &'static [&'static str] {
    crate::ir::abi::float_return_registers(cc)
}

/// The destination register an op writes to (if it writes a value register).
fn op_dst_reg(op: &Op) -> Option<&VReg> {
    match op {
        Op::Assign { dst, .. }
        | Op::Bin { dst, .. }
        | Op::Un { dst, .. }
        | Op::Load { dst, .. }
        | Op::CondLoad { dst, .. } => Some(dst),
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
pub(super) fn propagate_pointer_arithmetic(lf: &LlirFunction, tm: &mut TypeMap) {
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
