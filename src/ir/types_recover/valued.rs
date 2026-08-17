//! Value-keyed ("per-definition") type recovery.
//!
//! [`recover_types_valued`] is this module's front door and its only item with
//! a caller outside it. It produces a [`TypeMapV`](super::TypeMapV) — facts
//! keyed by the SSA value a particular definition produced rather than by the
//! architectural register that happened to carry it — which is the substrate
//! `recover_prototype_with_arm_vfp_args` joins against the raw-register
//! [`TypeMap`](super::TypeMap) built by [`recover_types`](super::recover_types).
//! It stays reachable at its old `crate::ir::types_recover::` path via the
//! `pub use` re-export in the parent; it was already `pub fn`, so nothing here
//! changed visibility.
//!
//! Everything else in this module is private and has no caller outside it:
//! the SSA operand pairing (`InstructionValues`, `instruction_values`,
//! `operand_value`), the frame-address predicates (`frame_base_aliases`,
//! `frame_slot`), the equivalence and phi-liveness helpers (`unify_values`,
//! `live_phi_values`), and the ABI live-in predicates
//! (`is_aapcs_core_word_live_in`, `is_sysv_integer_live_in`, `low_mask_width`).
//!
//! The width vocabulary shared with the raw-register pass —
//! [`reg_width_bytes`](super::reg_width_bytes) and
//! [`int_for_reg`](super::int_for_reg) — deliberately stays in the parent
//! module: both have callers on the raw-register side as well, so they are
//! shared vocabulary rather than helpers of this pass.

use std::collections::{HashMap, HashSet};

use crate::ir::ssa::{SsaInfo, SsaValue};
use crate::ir::types::{BinOp, LlirFunction, Op, VReg, Value};
use crate::ir::use_def::{def_uses, InstrAddr};

use super::{int_for_reg, reg_width_bytes, TypeHint, TypeMapV};

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

/// Registers carrying a stable address derived only by copies or a constant
/// displacement from an architectural stack/frame pointer.
///
/// ARM32 GCC commonly establishes `r7 = sp + 0` and spills incoming values
/// relative to `r7`. Following that value shape is safer than globally
/// declaring every use of callee-saved `r7` to be a frame access.
fn frame_base_aliases(lf: &LlirFunction) -> HashSet<VReg> {
    let mut bases = HashSet::from([
        VReg::phys("rbp"),
        VReg::phys("rsp"),
        VReg::phys("ebp"),
        VReg::phys("esp"),
        VReg::phys("x29"),
        VReg::phys("w29"),
        VReg::phys("sp"),
    ]);
    for _ in 0..8 {
        let mut grew = false;
        for block in &lf.blocks {
            for instruction in &block.instrs {
                let alias = match &instruction.op {
                    Op::Assign {
                        dst,
                        src: Value::Reg(source),
                    } if bases.contains(source) => Some(dst),
                    Op::Bin {
                        dst,
                        op: BinOp::Add | BinOp::Sub,
                        lhs: Value::Reg(base),
                        rhs: Value::Const(_),
                    } if bases.contains(base) => Some(dst),
                    Op::Bin {
                        dst,
                        op: BinOp::Add,
                        lhs: Value::Const(_),
                        rhs: Value::Reg(base),
                    } if bases.contains(base) => Some(dst),
                    _ => None,
                };
                if let Some(alias) = alias {
                    grew |= bases.insert(alias.clone());
                }
            }
        }
        if !grew {
            break;
        }
    }
    bases
}

fn frame_slot(
    addr: &crate::ir::types::MemOp,
    frame_bases: &HashSet<VReg>,
) -> Option<(String, i64)> {
    if addr.index.is_some() {
        return None;
    }
    match addr.base.as_ref() {
        Some(base @ VReg::Phys(name)) if frame_bases.contains(base) => {
            Some((name.clone(), addr.disp))
        }
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

/// Whether `value` is one exact caller-supplied AAPCS core-register word.
///
/// ARM32 spells all four integer argument containers `r0` through `r3`, so
/// their names carry neither source signedness nor a narrower view. Keep this
/// predicate exact: later versions are scratch lifetimes. The AAPCS boundary,
/// rather than the architecture-neutral register spelling, supplies the
/// four-byte container width.
fn is_aapcs_core_word_live_in(value: &SsaValue) -> bool {
    value.version == 0
        && matches!(
            &value.base,
            VReg::Phys(name) if matches!(name.as_str(), "r0" | "r1" | "r2" | "r3")
        )
}

/// Whether `value` is one exact SysV AMD64 integer-register live-in.
///
/// The 32-bit and narrower aliases are normalized to these six storage bases
/// by SSA.  Restricting derived narrow-home evidence to version zero prevents
/// a later scratch mask/store from rewriting the source contract.
fn is_sysv_integer_live_in(value: &SsaValue) -> bool {
    value.version == 0
        && matches!(
            &value.base,
            VReg::Phys(name)
                if matches!(name.as_str(), "rdi" | "rsi" | "rdx" | "rcx" | "r8" | "r9")
        )
}

fn low_mask_width(value: i64) -> Option<u8> {
    match value as u64 {
        0xff => Some(1),
        0xffff => Some(2),
        _ => None,
    }
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
    // Narrow SysV parameter homes are sometimes fed through a compiler copy
    // and low-bit mask (`edi -> eax; eax & 0xffff; mov [rbp-x], ax`).  These
    // edges are provenance-only: they must never unify the wide and narrow
    // values in the ordinary type lattice.
    let mut narrowing_sources: HashMap<SsaValue, (SsaValue, u8, bool)> = HashMap::new();
    let mut narrow_spill_candidates: Vec<((String, i64), SsaValue, u8)> = Vec::new();
    let mut strong_live_in_spills: HashSet<((String, i64), SsaValue)> = HashSet::new();
    let mut reloads: HashSet<SsaValue> = HashSet::new();
    let mut reload_slots: HashMap<SsaValue, (String, i64)> = HashMap::new();
    // Exact values consumed by a logical right shift. Unlike a merged
    // unsigned type hint, this is direct machine evidence that the source
    // operation interpreted this particular value as unsigned.
    let mut logical_shift_values: HashSet<SsaValue> = HashSet::new();
    // Exact caller-supplied values spilled into frame slots, together with the
    // store width. Width is part of the provenance proof: a later byte reload
    // may refine an incoming byte only when the entry value was itself stored
    // as a byte, rather than after an unrelated wider slot was partially read.
    let mut live_in_spills: HashMap<(String, i64), Vec<(SsaValue, u8)>> = HashMap::new();
    let live_phi_values = live_phi_values(lf, ssa);
    let frame_bases = frame_base_aliases(lf);

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
                Op::Load { addr, .. } | Op::CondLoad { addr, .. } => {
                    // CondLoad's predicate is the first use; ordinary Load
                    // starts directly with address operands. The fallback is
                    // after the address and does not affect pointer evidence.
                    let mut use_index = usize::from(matches!(&ins.op, Op::CondLoad { .. }));
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
                    if let Some(slot) = frame_slot(addr, &frame_bases) {
                        if let Some((_, dst)) = &values.def {
                            reloads.insert(dst.clone());
                            reload_slots.insert(dst.clone(), slot);
                        }
                    }
                }
                Op::Store { addr, .. } | Op::CondStore { addr, .. } => {
                    // CondStore's predicate is the first use; ordinary Store
                    // starts directly with address operands.
                    let mut use_index = usize::from(matches!(&ins.op, Op::CondStore { .. }));
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
                    if let Some(slot) = frame_slot(addr, &frame_bases) {
                        if let Some((_, source)) =
                            values.uses.get(use_index).and_then(|entry| entry.as_ref())
                        {
                            // Keep the exact stored value for now. GCC commonly
                            // emits `r3 = r1; strb r3, [frame]` for an AAPCS
                            // byte parameter, so the caller-supplied provenance
                            // may sit behind one or more pure copies. Those copy
                            // edges are resolved after this seed walk.
                            let sources = live_in_spills.entry(slot.clone()).or_default();
                            let spill = (source.clone(), addr.size.max(1));
                            if !sources.contains(&spill) {
                                sources.push(spill);
                            }
                            if block_idx == 0 && addr.size.max(1) <= 2 {
                                narrow_spill_candidates.push((
                                    slot,
                                    source.clone(),
                                    addr.size.max(1),
                                ));
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
                    ..
                } => {
                    if let Some((_, target)) = values.uses.first().and_then(Option::as_ref) {
                        tm.upsert(target.clone(), TypeHint::CodePointer);
                    }
                }
                Op::Bin {
                    op: BinOp::And,
                    lhs,
                    rhs,
                    ..
                } => {
                    let mut cursor = 0;
                    let lhs_value = operand_value(lhs, &values, &mut cursor);
                    let rhs_value = operand_value(rhs, &values, &mut cursor);
                    let masked_source = match (lhs, rhs) {
                        (Value::Reg(_), Value::Const(mask)) => low_mask_width(*mask).zip(lhs_value),
                        (Value::Const(mask), Value::Reg(_)) => low_mask_width(*mask).zip(rhs_value),
                        _ => None,
                    };
                    if let (Some((_, dst)), Some((width, source))) = (&values.def, masked_source) {
                        narrowing_sources.insert(dst.clone(), (source, width, true));
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
                        logical_shift_values.insert(lhs_value.clone());
                        let hint = TypeHint::Int {
                            signed: false,
                            width: reg_width_bytes(raw),
                        };
                        tm.upsert(lhs_value.clone(), hint);
                        // AAPCS core registers do not encode signedness or a
                        // narrower source type in their names. Consuming the
                        // exact caller-supplied word with LSR is direct
                        // unsigned-word evidence, even when pointer arithmetic
                        // later derives an MMIO address from the same value.
                        if is_aapcs_core_word_live_in(&lhs_value) {
                            tm.upsert_parameter_refinement(lhs_value, hint);
                        }
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
                        if let Some((_, dst)) = &values.def {
                            let available = if matches!(&ins.op, Op::Trunc { .. }) {
                                to.bytes()
                            } else {
                                from.bytes()
                            }
                            .min(u8::MAX as u16) as u8;
                            narrowing_sources.insert(
                                dst.clone(),
                                (
                                    source.clone(),
                                    available,
                                    matches!(&ins.op, Op::Trunc { .. }),
                                ),
                            );
                        }
                        tm.upsert(
                            source,
                            TypeHint::Int {
                                signed,
                                width: from.bytes().min(u8::MAX as u16) as u8,
                            },
                        );
                    }
                }
                _ => {}
            }
        }
    }

    // Resolve frame-spill provenance through exact copies only. This admits
    // the real ARM `r1 -> r3 -> strb` prologue without treating arithmetic,
    // calls, or later scratch reuse as caller input. SSA definitions make the
    // predecessor relation single-valued; the visited set is a fail-closed
    // guard against malformed cyclic input.
    let copy_sources: HashMap<SsaValue, SsaValue> = copy_edges.iter().cloned().collect();
    for spills in live_in_spills.values_mut() {
        let mut resolved = Vec::new();
        for (source, width) in std::mem::take(spills) {
            let mut candidate = source;
            let mut visited = HashSet::new();
            loop {
                if candidate.version == 0 && matches!(candidate.base, VReg::Phys(_)) {
                    let spill = (candidate, width);
                    if !resolved.contains(&spill) {
                        resolved.push(spill);
                    }
                    break;
                }
                if !visited.insert(candidate.clone()) {
                    break;
                }
                let Some(predecessor) = copy_sources.get(&candidate) else {
                    break;
                };
                candidate = predecessor.clone();
            }
        }
        *spills = resolved;
    }
    live_in_spills.retain(|_, spills| !spills.is_empty());

    // Admit a compiler-derived narrow parameter home only when the chain is
    // rooted at one exact SysV live-in, contains an explicit low-width mask or
    // truncation, and that live-in has no ordinary full-width spill.  The last
    // condition distinguishes `f(short x)` from
    // `f(int x) { short local = x; }`, whose prologue first saves `x` at four
    // bytes.  Multiple distinct narrow destinations are also ambiguous and
    // fail closed.
    let exact_spilled_sources: HashSet<SsaValue> = live_in_spills
        .values()
        .flatten()
        .map(|(source, _)| source.clone())
        .collect();
    let mut derived: HashMap<SsaValue, Vec<((String, i64), u8)>> = HashMap::new();
    for (slot, source, spill_width) in narrow_spill_candidates {
        let mut candidate = source;
        let mut narrowed = false;
        let mut visited = HashSet::new();
        loop {
            if candidate.version == 0 && matches!(candidate.base, VReg::Phys(_)) {
                if narrowed
                    && is_sysv_integer_live_in(&candidate)
                    && !exact_spilled_sources.contains(&candidate)
                {
                    derived
                        .entry(candidate)
                        .or_default()
                        .push((slot.clone(), spill_width));
                }
                break;
            }
            if !visited.insert(candidate.clone()) {
                break;
            }
            if let Some(predecessor) = copy_sources.get(&candidate) {
                candidate = predecessor.clone();
                continue;
            }
            let Some((predecessor, available_width, edge_narrows)) =
                narrowing_sources.get(&candidate)
            else {
                break;
            };
            if *available_width < spill_width {
                break;
            }
            narrowed |= edge_narrows;
            candidate = predecessor.clone();
        }
    }
    for (source, mut candidates) in derived {
        candidates.sort();
        candidates.dedup();
        if candidates.len() != 1 {
            continue;
        }
        let (slot, width) = candidates.pop().expect("one narrow candidate");
        strong_live_in_spills.insert((slot.clone(), source.clone()));
        live_in_spills
            .entry(slot)
            .or_default()
            .push((source, width));
    }

    let live_in_reloads: HashSet<SsaValue> = reload_slots
        .iter()
        .filter(|(_, slot)| live_in_spills.contains_key(*slot))
        .map(|(value, _)| value.clone())
        .collect();

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

    // Start from exact SSA values used as memory bases, then walk only
    // value-preserving copies, live phis, and structurally identified pointer
    // arithmetic backwards. A raw-register pointer hint is not sufficient:
    // ARM call-heavy functions routinely reuse r1/r2 as later pointer scratch,
    // which must not retype the incoming full-width integer parameters.
    let mut address_values = HashSet::new();
    for (block_idx, block) in lf.blocks.iter().enumerate() {
        for (instr_idx, instruction) in block.instrs.iter().enumerate() {
            let address_use_index = match instruction.op {
                Op::Load { .. } | Op::Store { .. } => 0,
                Op::CondLoad { .. } | Op::CondStore { .. } => 1,
                _ => continue,
            };
            let values = instruction_values(
                lf,
                ssa,
                InstrAddr {
                    block_idx,
                    instr_idx,
                },
            );
            if let Some((_, base)) = values.uses.get(address_use_index).and_then(Option::as_ref) {
                address_values.insert(base.clone());
            }
        }
    }
    for _ in 0..16 {
        let mut grew = false;
        for (dst, source) in &copy_edges {
            if address_values.contains(dst) {
                grew |= address_values.insert(source.clone());
            }
        }
        for phi in &ssa.phis {
            let result = SsaValue {
                base: phi.base.clone(),
                version: phi.dst_version,
            };
            if !live_phi_values.contains(&result) || !address_values.contains(&result) {
                continue;
            }
            for (_, version) in &phi.incoming {
                grew |= address_values.insert(SsaValue {
                    base: phi.base.clone(),
                    version: *version,
                });
            }
        }
        for (block_idx, block) in lf.blocks.iter().enumerate() {
            for (instr_idx, instruction) in block.instrs.iter().enumerate() {
                let Op::Bin {
                    op: BinOp::Add | BinOp::Sub,
                    lhs,
                    rhs,
                    ..
                } = &instruction.op
                else {
                    continue;
                };
                let values = instruction_values(
                    lf,
                    ssa,
                    InstrAddr {
                        block_idx,
                        instr_idx,
                    },
                );
                let Some((_, dst)) = &values.def else {
                    continue;
                };
                if !address_values.contains(dst) {
                    continue;
                }
                let mut cursor = 0;
                let lhs_value = operand_value(lhs, &values, &mut cursor);
                let rhs_value = operand_value(rhs, &values, &mut cursor);
                let is_offset = |operand: &Value, value: &Option<SsaValue>| match operand {
                    Value::Const(_) => true,
                    Value::Reg(_) => value
                        .as_ref()
                        .is_some_and(|candidate| offsets.contains(candidate)),
                    Value::Addr(_) => false,
                };
                let is_live_in_reload = |value: &Option<SsaValue>| {
                    value
                        .as_ref()
                        .is_some_and(|candidate| live_in_reloads.contains(candidate))
                };
                let base = if is_live_in_reload(&lhs_value) && !is_live_in_reload(&rhs_value) {
                    lhs_value
                } else if matches!(instruction.op, Op::Bin { op: BinOp::Add, .. })
                    && is_live_in_reload(&rhs_value)
                    && !is_live_in_reload(&lhs_value)
                {
                    rhs_value
                } else if is_offset(rhs, &rhs_value) && !is_offset(lhs, &lhs_value) {
                    lhs_value
                } else if matches!(instruction.op, Op::Bin { op: BinOp::Add, .. })
                    && is_offset(lhs, &lhs_value)
                    && !is_offset(rhs, &rhs_value)
                {
                    rhs_value
                } else {
                    None
                };
                if let Some(base) = base {
                    grew |= address_values.insert(base);
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
                        let is_live_in_reload = |value: &Option<SsaValue>| {
                            value
                                .as_ref()
                                .is_some_and(|value| live_in_reloads.contains(value))
                        };
                        let base = if is_live_in_reload(&lhs_value)
                            && !is_live_in_reload(&rhs_value)
                        {
                            lhs_value
                        } else if is_live_in_reload(&rhs_value) && !is_live_in_reload(&lhs_value) {
                            rhs_value
                        } else if is_reload(&lhs_value) && !is_reload(&rhs_value) {
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
                        let Some(slot) = frame_slot(addr, &frame_bases) else {
                            continue;
                        };
                        let Some(sources) = live_in_spills.get(&slot) else {
                            continue;
                        };
                        let Some((_, dst)) = &values.def else {
                            continue;
                        };
                        match tm.get(dst) {
                            Some(TypeHint::Pointer { pointee_width })
                                if address_values.contains(dst) =>
                            {
                                for (source, stored_width) in sources {
                                    if *stored_width != addr.size.max(1) {
                                        continue;
                                    }
                                    let hint = TypeHint::Pointer { pointee_width };
                                    changed |= tm.upsert(source.clone(), hint);
                                    changed |= tm.upsert_parameter_refinement(source.clone(), hint);
                                }
                            }
                            Some(TypeHint::Int { signed, width }) => {
                                // A narrow entry spill followed by a same-width
                                // reload and explicit ZExt/SExt is source-level
                                // parameter evidence, not just storage reuse. At
                                // full width, accept only unsigned evidence from
                                // an operation such as logical right shift: a
                                // default signed machine-word fact is not enough
                                // to distinguish an integer from a pointer.
                                for (source, stored_width) in sources {
                                    if *stored_width != addr.size.max(1) {
                                        continue;
                                    }
                                    let narrow_exact = width == *stored_width && width <= 2;
                                    let aapcs_unsigned_word = !signed
                                        && *stored_width == 4
                                        && logical_shift_values.contains(dst)
                                        && is_aapcs_core_word_live_in(source);
                                    if !narrow_exact && !aapcs_unsigned_word {
                                        continue;
                                    }
                                    let hint = TypeHint::Int {
                                        signed,
                                        width: addr.size.max(1),
                                    };
                                    changed |= tm.upsert(source.clone(), hint);
                                    changed |= if narrow_exact
                                        && strong_live_in_spills
                                            .contains(&(slot.clone(), source.clone()))
                                    {
                                        tm.upsert_strong_parameter_refinement(source.clone(), hint)
                                    } else {
                                        tm.upsert_parameter_refinement(source.clone(), hint)
                                    };
                                }
                            }
                            _ => {}
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
