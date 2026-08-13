//! Typed-MIR adapter for stable object and cursor-lifetime evidence.

use std::collections::{BTreeMap, BTreeSet};

use crate::ir::memory_objects::{
    AccessRole, AccessSource, LayoutConflict, MemoryObjectBuilder, MemoryStateIdentity,
    ObjectIdentity, ObjectOrigin, RawAccess,
};
use crate::ir::memory_ssa::primary_region_for_memop;
use crate::ir::mir::{Definition, InstructionId, MirFunction, ValueId};
use crate::ir::types::{BinOp, LlirFunction, MemOp, Op, Value};
use crate::program::image::ProgramImage;

#[derive(Debug, Clone, PartialEq, Eq)]
struct AffineFact {
    root: ValueId,
    offset: i64,
    origin: ObjectOrigin,
}

#[derive(Debug, Default)]
struct ResolvedAffine {
    facts: BTreeMap<ValueId, AffineFact>,
    strides: BTreeMap<ValueId, BTreeSet<i64>>,
}

/// Attach direct affine access paths to the already verified MIR memory graph.
pub(crate) fn attach(function: &mut MirFunction, llir: &LlirFunction, image: &ProgramImage) {
    let operations = llir
        .blocks
        .iter()
        .flat_map(|block| block.instrs.iter().map(|instruction| &instruction.op))
        .collect::<Vec<_>>();
    if operations.len() != function.instructions().len() {
        return;
    }

    let resolved = resolve_affine_values(function, &operations);
    let mut builder = MemoryObjectBuilder::default();
    for (root, strides) in &resolved.strides {
        for stride in strides {
            builder.observe_stride(*root, *stride);
        }
    }

    for (instruction_index, operation) in operations.iter().enumerate() {
        let instruction = InstructionId(instruction_index);
        let Some((memop, role, base_use_index)) = direct_memop(operation) else {
            continue;
        };
        let region = primary_region_for_memop(memop, image);
        let Some(memory_access) = function.instructions()[instruction_index]
            .memory_effects
            .iter()
            .copied()
            .find(|access| function.memory_accesses()[access.0].region == region)
        else {
            continue;
        };
        let access = &function.memory_accesses()[memory_access.0];
        let memory_state = match role {
            AccessRole::Read => access.input,
            AccessRole::Write => match access.output {
                Some(output) => output,
                None => continue,
            },
        };

        let (object, cursor, offset, origin) = if let Some(use_index) = base_use_index {
            let Some(cursor) = use_value(function, instruction, use_index) else {
                continue;
            };
            let fact = resolved.facts.get(&cursor);
            let root = fact.map_or(cursor, |fact| fact.root);
            let Some(offset) = fact
                .map_or(Some(0), |fact| Some(fact.offset))
                .and_then(|base| base.checked_add(memop.disp))
            else {
                builder.conflict(root, LayoutConflict::UnclassifiedDefinition);
                continue;
            };
            (
                ObjectIdentity::MirValue(root),
                ObjectIdentity::MirValue(cursor),
                offset,
                fact.map(|fact| fact.origin.clone()),
            )
        } else if let Some(segment) = &memop.segment {
            let identity = ObjectIdentity::TlsAddress {
                segment: segment.clone(),
                offset: memop.disp,
            };
            (
                identity.clone(),
                identity,
                0,
                Some(ObjectOrigin::TlsAddress {
                    segment: segment.clone(),
                    offset: memop.disp,
                }),
            )
        } else {
            let Ok(address) = u64::try_from(memop.disp) else {
                continue;
            };
            let identity = ObjectIdentity::AbsoluteAddress(address);
            (
                identity.clone(),
                identity,
                0,
                Some(ObjectOrigin::Address(address)),
            )
        };

        builder.observe_alias(object.clone(), cursor.clone());
        if let Some(origin) = origin {
            builder.observe_origin(object.clone(), origin);
        }
        builder.observe_access(
            object,
            RawAccess {
                cursor,
                offset,
                width: memop.size,
                role,
                source: AccessSource::MirInstruction(instruction),
                memory_region: Some(region),
                memory_state: Some(MemoryStateIdentity::Mir(memory_state)),
                mir_access: Some(memory_access),
            },
        );
    }

    let model = builder.finish();
    let links = model
        .objects()
        .iter()
        .flat_map(|object| {
            object
                .accesses
                .iter()
                .filter_map(move |access| access.mir_access.map(|access| (access, object.id)))
        })
        .collect::<Vec<_>>();
    for (access, object) in links {
        if let Some(record) = function.memory_accesses.get_mut(access.0) {
            record.object = Some(object);
        }
    }
    function.object_model = model;
}

fn resolve_affine_values(function: &MirFunction, operations: &[&Op]) -> ResolvedAffine {
    let mut facts = BTreeMap::new();
    for value in function.values() {
        if !matches!(value.definition, Definition::Input) {
            continue;
        }
        let register = &function.storages()[value.storage.0].register;
        let stack = matches!(register, crate::ir::types::VReg::Phys(name)
            if function.target.registers().is_stack_pointer(name)
                || function.target.registers().is_frame_pointer(name));
        let origin = if stack {
            ObjectOrigin::StackValue(value.id)
        } else {
            ObjectOrigin::ParameterPointee(value.id)
        };
        facts.insert(
            value.id,
            AffineFact {
                root: value.id,
                offset: 0,
                origin,
            },
        );
    }

    let mut strides = BTreeMap::<ValueId, BTreeSet<i64>>::new();
    loop {
        propagate_acyclic(function, operations, &mut facts);
        let mut recurrence_changed = false;
        for value in function.values() {
            if facts.contains_key(&value.id) {
                continue;
            }
            let Definition::Phi { incoming, .. } = &value.definition else {
                continue;
            };
            let known = incoming
                .iter()
                .filter_map(|(_, incoming)| facts.get(incoming))
                .collect::<Vec<_>>();
            let Some(first) = known.first() else {
                continue;
            };
            if !known
                .iter()
                .all(|fact| fact.root == first.root && fact.offset == first.offset)
            {
                continue;
            }
            let unresolved = incoming
                .iter()
                .filter(|(_, incoming)| !facts.contains_key(incoming))
                .map(|(_, incoming)| *incoming)
                .collect::<Vec<_>>();
            if unresolved.is_empty() {
                continue;
            }
            let Some(steps) = unresolved
                .iter()
                .map(|incoming| recurrence_step(function, operations, *incoming, value.id))
                .collect::<Option<Vec<_>>>()
            else {
                continue;
            };
            let fact = (*first).clone();
            for step in steps {
                strides.entry(fact.root).or_default().insert(step);
            }
            facts.insert(value.id, fact);
            recurrence_changed = true;
        }
        if !recurrence_changed {
            break;
        }
    }
    ResolvedAffine { facts, strides }
}

fn propagate_acyclic(
    function: &MirFunction,
    operations: &[&Op],
    facts: &mut BTreeMap<ValueId, AffineFact>,
) {
    let mut changed = true;
    while changed {
        changed = false;
        for value in function.values() {
            if facts.contains_key(&value.id) {
                continue;
            }
            let candidate = match &value.definition {
                Definition::InstructionOutput { instruction, .. } => {
                    operations.get(instruction.0).and_then(|operation| {
                        instruction_fact(function, value.id, *instruction, operation, facts)
                    })
                }
                Definition::Phi { incoming, .. } => {
                    let incoming = incoming
                        .iter()
                        .map(|(_, value)| facts.get(value))
                        .collect::<Option<Vec<_>>>();
                    incoming.and_then(|incoming| {
                        let first = incoming.first()?;
                        incoming
                            .iter()
                            .all(|fact| fact.root == first.root && fact.offset == first.offset)
                            .then(|| (*first).clone())
                    })
                }
                _ => None,
            };
            if let Some(candidate) = candidate {
                facts.insert(value.id, candidate);
                changed = true;
            }
        }
    }
}

fn recurrence_step(
    function: &MirFunction,
    operations: &[&Op],
    incoming: ValueId,
    phi: ValueId,
) -> Option<i64> {
    let Definition::InstructionOutput { instruction, .. } =
        &function.values().get(incoming.0)?.definition
    else {
        return None;
    };
    let Op::Bin { op, lhs, rhs, .. } = operations.get(instruction.0)? else {
        return None;
    };
    let displacement = match (op, lhs, rhs) {
        (BinOp::Add, Value::Reg(_), Value::Const(value))
        | (BinOp::Add, Value::Const(value), Value::Reg(_)) => *value,
        (BinOp::Sub, Value::Reg(_), Value::Const(value)) => value.checked_neg()?,
        _ => return None,
    };
    (use_value(function, *instruction, 0)? == phi).then_some(displacement)
}

fn instruction_fact(
    function: &MirFunction,
    output: ValueId,
    instruction: InstructionId,
    operation: &Op,
    facts: &BTreeMap<ValueId, AffineFact>,
) -> Option<AffineFact> {
    match operation {
        Op::Assign {
            src: Value::Addr(address),
            ..
        } => Some(AffineFact {
            root: output,
            offset: 0,
            origin: ObjectOrigin::Address(*address),
        }),
        Op::Assign {
            src: Value::Reg(_), ..
        } => facts.get(&use_value(function, instruction, 0)?).cloned(),
        Op::Bin { op, lhs, rhs, .. } => {
            let (source_index, displacement) = match (op, lhs, rhs) {
                (BinOp::Add, Value::Reg(_), Value::Const(value))
                | (BinOp::Add, Value::Const(value), Value::Reg(_)) => (0, *value),
                (BinOp::Sub, Value::Reg(_), Value::Const(value)) => (0, value.checked_neg()?),
                _ => return None,
            };
            let mut fact = facts
                .get(&use_value(function, instruction, source_index)?)?
                .clone();
            fact.offset = fact.offset.checked_add(displacement)?;
            Some(fact)
        }
        Op::Call { .. } => Some(AffineFact {
            root: output,
            offset: 0,
            origin: ObjectOrigin::CallResult(
                crate::ir::memory_objects::AccessSource::MirInstruction(instruction),
            ),
        }),
        _ => None,
    }
}

fn use_value(function: &MirFunction, instruction: InstructionId, index: usize) -> Option<ValueId> {
    function
        .instructions()
        .get(instruction.0)?
        .uses
        .iter()
        .filter_map(|use_| function.uses().get(use_.0))
        .find(|use_| use_.index == index)
        .map(|use_| use_.value)
}

fn direct_memop(operation: &Op) -> Option<(&MemOp, AccessRole, Option<usize>)> {
    let (memop, role, first_address_use) = match operation {
        Op::Load { addr, .. } => (addr, AccessRole::Read, 0),
        Op::CondLoad { addr, .. } => (addr, AccessRole::Read, 1),
        Op::Store { addr, .. } => (addr, AccessRole::Write, 0),
        Op::CondStore { addr, .. } => (addr, AccessRole::Write, 1),
        _ => return None,
    };
    if memop.index.is_some() {
        return None;
    }
    Some((memop, role, memop.base.as_ref().map(|_| first_address_use)))
}
