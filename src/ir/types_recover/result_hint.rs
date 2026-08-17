//! Joining result-type evidence into a single prototype return fact.
//!
//! A function's return type is argued from several weaker observations: the
//! storage class the ABI dictates ([`ResultHintClass`], `result_hint_class`),
//! what a particular defining op proves about the value it produced
//! ([`qualified_result_hint`]), whether a trial output register is genuinely
//! dedicated to the return ([`output_trial_is_dedicated`]), and whether a
//! call's result is consumed only by a guard ([`call_result_has_only_guard_uses`]).
//! [`join_result_hints`] is the join itself, and [`non_return_live_values`]
//! supplies the liveness backdrop the trials are judged against.
//!
//! `recover_prototype_with_arm_vfp_args` in the parent is the only consumer of
//! this module; `result_hint_class` is private to it.

use std::collections::{HashMap, HashSet};

use crate::ir::ssa::{SsaInfo, SsaValue};
use crate::ir::types::{LlirFunction, Op, Value};
use crate::ir::use_def::{def_uses, InstrAddr};

use super::{
    abi_pointer_width, normalize_value_hint_for_abi, scalar_float_intrinsic_width, TypeHint,
    TypeMapV,
};

/// A result fact strong enough to cross the SSA-to-source prototype boundary.
///
/// A narrow load cannot contain a machine pointer, so its scalar class and
/// width are conclusive. A pointer-width load remains unknown: it may be an
/// integer or a pointer read from memory, and guessing either would reproduce
/// the flow-insensitive contamination this prototype object is meant to stop.
pub(super) fn qualified_result_hint(
    op: &Op,
    valued: &TypeMapV,
    value: &SsaValue,
    cc: crate::ir::call_args::CallConv,
    storage_class: ResultHintClass,
) -> Option<TypeHint> {
    if storage_class == ResultHintClass::Float {
        let Op::Intrinsic {
            name, ins, outs, ..
        } = op
        else {
            return None;
        };
        let semantic_width = scalar_float_intrinsic_width(name, ins, outs)?;
        let declared_width = outs
            .iter()
            .find(|(register, _)| register == &value.base)
            .map(|(_, width)| u8::try_from(width.bytes()).expect("LLIR width fits in u8"))?;
        return (declared_width == semantic_width).then_some(TypeHint::Float {
            width: semantic_width,
        });
    }

    match op {
        Op::Load { addr, .. } | Op::CondLoad { addr, .. }
            if addr.size.max(1) < abi_pointer_width(cc) =>
        {
            Some(TypeHint::Int {
                signed: true,
                width: addr.size.max(1),
            })
        }
        Op::Assign {
            src: Value::Reg(_) | Value::Const(_),
            ..
        }
        | Op::Bin { .. }
        | Op::Un { .. }
        | Op::Cmp { .. }
        | Op::ZExt { .. }
        | Op::SExt { .. }
        | Op::Trunc { .. } => valued
            .get(value)
            .map(|hint| normalize_value_hint_for_abi(hint, cc)),
        // Calls, full-width loads, address constants, conditional updates, and
        // opaque definitions need stronger prototype or merge evidence before
        // they can safely decide pointer-vs-scalar class.
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum ResultHintClass {
    Pointer,
    Integer,
    Float,
}

fn result_hint_class(hint: TypeHint) -> ResultHintClass {
    match hint {
        TypeHint::Pointer { .. } | TypeHint::CodePointer => ResultHintClass::Pointer,
        TypeHint::Int { .. } | TypeHint::BoolLike => ResultHintClass::Integer,
        TypeHint::Float { .. } => ResultHintClass::Float,
    }
}

/// Join independently qualified return definitions without inventing a C type
/// that cannot represent all of them.
///
/// Ghidra's `propagateAcrossReturns` first chooses one canonical return type,
/// then propagates it only across compatible return storage. Kuna preserves the
/// same constraint. Our smaller lattice has no union type, so pointer/scalar
/// conflicts fail closed except for C's one compatible scalar value: a literal
/// zero used as a null pointer constant.
pub(super) fn join_result_hints(facts: &[(TypeHint, bool)]) -> Option<TypeHint> {
    let mut joined = None;
    let mut joined_class = None;
    let mut saw_nonnull_scalar = false;

    for (hint, is_literal_null) in facts {
        let class = result_hint_class(*hint);
        if class == ResultHintClass::Integer && !is_literal_null {
            saw_nonnull_scalar = true;
        }
        match joined_class {
            None => {
                joined = Some(*hint);
                joined_class = Some(class);
            }
            Some(current_class) if current_class == class && joined == Some(*hint) => {}
            Some(current_class) if current_class == class => return None,
            Some(current_class)
                if !saw_nonnull_scalar
                    && matches!(
                        (current_class, class),
                        (ResultHintClass::Pointer, ResultHintClass::Integer)
                            | (ResultHintClass::Integer, ResultHintClass::Pointer)
                    ) =>
            {
                // Every scalar fact seen so far is the literal zero. Preserve
                // the pointer class regardless of branch traversal order.
                if class == ResultHintClass::Pointer {
                    joined = Some(*hint);
                    joined_class = Some(ResultHintClass::Pointer);
                }
            }
            Some(_) => return None,
        }
    }
    joined
}

/// Decide whether one return-register definition is dedicated to the ABI
/// output trial rather than residue from another computation.
///
/// x86 32-bit writes are represented as a semantic write followed by a
/// same-storage zero-extension into the 64-bit parent. Looking only at the
/// final synthetic definition would call every such value "return-only". Walk
/// back through those same-storage view/copy nodes and require the ancestor to
/// have no use except the forwarding node. This is the compact LLIR analogue
/// of Ghidra's incidental COPY/SUBPIECE traversal in `ancestorOpUse` and Kuna's
/// `ancestor_op_use` port.
pub(super) fn output_trial_is_dedicated(
    lf: &LlirFunction,
    ssa: &SsaInfo,
    candidate: &SsaValue,
    definitions: &HashMap<SsaValue, InstrAddr>,
    non_return_live: &HashSet<SsaValue>,
) -> bool {
    let mut current = candidate.clone();
    let mut visited = HashSet::new();

    while visited.insert(current.clone()) {
        if non_return_live.contains(&current) {
            return false;
        }

        let Some(addr) = definitions.get(&current).copied() else {
            return false;
        };
        let op = &lf.blocks[addr.block_idx].instrs[addr.instr_idx].op;
        let forwards_same_storage = matches!(
            op,
            Op::Assign {
                src: Value::Reg(_),
                ..
            } | Op::ZExt {
                src: Value::Reg(_),
                ..
            } | Op::SExt {
                src: Value::Reg(_),
                ..
            } | Op::Trunc {
                src: Value::Reg(_),
                ..
            }
        );
        if !forwards_same_storage {
            if matches!(
                op,
                Op::Call {
                    effects: Some(effects),
                    ..
                } if !effects.result_is_source_value
            ) {
                return false;
            }
            return true;
        }
        let Some(source) = ssa.use_value(lf, addr, 0) else {
            return true;
        };
        if source.base != current.base {
            return true;
        }
        current = source;
    }
    false
}

/// Whether a call result's only explicit consumption is a pure predicate chain.
///
/// `test rax, rax; je fatal; ret` is the canonical optimized shape: the call
/// value is read by control flow *and* is the unchanged machine result on the
/// only returning path.  Treating every compared value as incidental loses
/// that output.  Follow exact SSA uses and allow only view-preserving copies,
/// TEST's self-AND, comparisons, and the final conditional branch; any store,
/// arithmetic, argument use, or other side effect fails closed.
pub(super) fn call_result_has_only_guard_uses(
    lf: &LlirFunction,
    ssa: &SsaInfo,
    candidate: &SsaValue,
    definitions: &HashMap<SsaValue, InstrAddr>,
) -> bool {
    let Some(definition) = definitions.get(candidate) else {
        return false;
    };
    if !matches!(
        &lf.blocks[definition.block_idx].instrs[definition.instr_idx].op,
        Op::Call {
            effects: Some(effects),
            ..
        } if effects.result_is_source_value
    ) {
        return false;
    }

    let mut pending = vec![candidate.clone()];
    let mut visited = HashSet::new();
    let mut saw_conditional_branch = false;
    while let Some(value) = pending.pop() {
        if !visited.insert(value.clone()) {
            continue;
        }
        for (block_idx, block) in lf.blocks.iter().enumerate() {
            for (instr_idx, instruction) in block.instrs.iter().enumerate() {
                let addr = InstrAddr {
                    block_idx,
                    instr_idx,
                };
                let (_, uses) = def_uses(&instruction.op);
                let uses_value = (0..uses.len())
                    .any(|index| ssa.use_value(lf, addr, index).as_ref() == Some(&value));
                if !uses_value {
                    continue;
                }
                match &instruction.op {
                    Op::CondJump { .. } => saw_conditional_branch = true,
                    Op::Assign { .. }
                    | Op::ZExt { .. }
                    | Op::SExt { .. }
                    | Op::Trunc { .. }
                    | Op::Cmp { .. }
                    | Op::Bin {
                        op: crate::ir::types::BinOp::And,
                        ..
                    } => {
                        let Some(next) = ssa.def_value(lf, addr) else {
                            return false;
                        };
                        pending.push(next);
                    }
                    _ => return false,
                }
            }
        }
    }
    saw_conditional_branch
}

/// Values whose dataflow reaches an observable use other than the implicit
/// function return.
///
/// The lifters materialise flag calculations for every arithmetic instruction,
/// even when those flags are dead. Raw use-counting therefore mistakes a dead
/// flag fan-out for source-level consumption. Seed liveness only at side-effect
/// and control-flow operations, then propagate backwards through SSA defs and
/// phi edges. An accumulator returned after a loop stays output-only; the same
/// register used by the loop condition or a store is live residue.
pub(super) fn non_return_live_values(lf: &LlirFunction, ssa: &SsaInfo) -> HashSet<SsaValue> {
    let mut dependencies: HashMap<SsaValue, Vec<SsaValue>> = HashMap::new();
    let mut live = HashSet::new();

    for (block_idx, block) in lf.blocks.iter().enumerate() {
        for (instr_idx, ins) in block.instrs.iter().enumerate() {
            let addr = InstrAddr {
                block_idx,
                instr_idx,
            };
            let (raw_def, raw_uses) = def_uses(&ins.op);
            let uses: Vec<SsaValue> = (0..raw_uses.len())
                .filter_map(|use_idx| ssa.use_value(lf, addr, use_idx))
                .collect();
            if let Some(definition) = raw_def.as_ref().and_then(|_| ssa.def_value(lf, addr)) {
                dependencies.insert(definition, uses.clone());
            }
            let observable = raw_def.is_none()
                || matches!(ins.op, Op::Call { .. })
                || matches!(
                    ins.op,
                    Op::Intrinsic {
                        reads_mem: true,
                        ..
                    } | Op::Intrinsic {
                        writes_mem: true,
                        ..
                    }
                );
            if observable && !matches!(ins.op, Op::Return | Op::Nop | Op::Jump { .. }) {
                live.extend(uses);
            }
        }
    }

    for phi in &ssa.phis {
        dependencies.insert(
            SsaValue {
                base: phi.base.clone(),
                version: phi.dst_version,
            },
            phi.incoming
                .iter()
                .map(|(_, version)| SsaValue {
                    base: phi.base.clone(),
                    version: *version,
                })
                .collect(),
        );
    }

    loop {
        let before = live.len();
        let frontier: Vec<SsaValue> = live.iter().cloned().collect();
        for value in frontier {
            if let Some(inputs) = dependencies.get(&value) {
                live.extend(inputs.iter().cloned());
            }
        }
        if live.len() == before {
            break;
        }
    }
    live
}
