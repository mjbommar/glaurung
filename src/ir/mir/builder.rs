//! Deterministic LLIR-to-MIR construction.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::ir::ssa::{canon_gpr_for_target, compute_ssa_for_target, SsaValue};
use crate::ir::types::{phys_reg_width, LlirFunction, Op, VReg, Width};
use crate::ir::use_def::{defs_uses, InstrAddr};
use crate::target::TargetSpec;

use super::model::{
    BlockId, Definition, InstructionId, MirBlock, MirFunction, MirInstruction, MirStorage, MirUse,
    MirValue, StorageId, UseId, ValueId,
};
use super::verify::verify;

pub fn lower_verified(llir: &LlirFunction, target: TargetSpec) -> Result<MirFunction, Vec<String>> {
    if llir.blocks.is_empty() {
        return Err(vec!["LLIR function has no blocks".to_string()]);
    }
    let mir = lower(llir, target);
    let errors = verify(&mir);
    if errors.is_empty() {
        Ok(mir)
    } else {
        Err(errors)
    }
}

pub(super) fn lower(llir: &LlirFunction, target: TargetSpec) -> MirFunction {
    let ssa = compute_ssa_for_target(llir, target);
    let va_to_block: BTreeMap<u64, BlockId> = llir
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start_va, BlockId(index)))
        .collect();
    let mut predecessors = vec![Vec::new(); llir.blocks.len()];
    for (index, block) in llir.blocks.iter().enumerate() {
        for successor in &block.succs {
            if let Some(successor) = va_to_block.get(successor) {
                predecessors[successor.0].push(BlockId(index));
            }
        }
    }
    for list in &mut predecessors {
        list.sort_unstable();
        list.dedup();
    }
    let reachable = reachable_blocks(llir, &va_to_block);

    let mut registers = BTreeSet::new();
    for block in &llir.blocks {
        for instruction in &block.instrs {
            let (definitions, uses) = defs_uses(&instruction.op);
            registers.extend(
                definitions
                    .into_iter()
                    .chain(uses)
                    .map(|register| canon_gpr_for_target(target, &register)),
            );
        }
    }
    for phi in &ssa.phis {
        registers.insert(phi.base.clone());
    }
    let storages: Vec<MirStorage> = registers
        .into_iter()
        .enumerate()
        .map(|(index, register)| MirStorage {
            id: StorageId(index),
            width: storage_width(target, &register),
            register,
        })
        .collect();
    let storage_by_register: BTreeMap<VReg, StorageId> = storages
        .iter()
        .map(|storage| (storage.register.clone(), storage.id))
        .collect();

    let mut instructions = Vec::new();
    let mut instruction_ids = vec![Vec::new(); llir.blocks.len()];
    for (block_index, block) in llir.blocks.iter().enumerate() {
        for (index, instruction) in block.instrs.iter().enumerate() {
            let id = InstructionId(instructions.len());
            instruction_ids[block_index].push(id);
            instructions.push(MirInstruction {
                id,
                block: BlockId(block_index),
                index,
                source_va: instruction.va,
                uses: Vec::new(),
                outputs: Vec::new(),
                memory_effects: Vec::new(),
            });
        }
    }

    let mut values = Vec::new();
    let mut value_by_ssa = BTreeMap::<SsaValue, ValueId>::new();

    // Inputs are explicit definitions rather than an overloaded SSA version.
    let mut live_ins = BTreeSet::new();
    for block in &llir.blocks {
        for (instruction_index, instruction) in block.instrs.iter().enumerate() {
            let addr = InstrAddr {
                block_idx: va_to_block[&block.start_va].0,
                instr_idx: instruction_index,
            };
            for use_index in 0..defs_uses(&instruction.op).1.len() {
                if let Some(value) = ssa.use_value(llir, addr, use_index) {
                    if value.version == 0 {
                        live_ins.insert(value);
                    }
                }
            }
        }
    }
    for phi in &ssa.phis {
        for (_, version) in &phi.incoming {
            if *version == 0 {
                live_ins.insert(SsaValue {
                    base: phi.base.clone(),
                    version: 0,
                });
            }
        }
    }
    for input in live_ins {
        ensure_value(
            &mut values,
            &mut value_by_ssa,
            &storage_by_register,
            &storages,
            input,
            Definition::Input,
            None,
        );
    }

    // Phi identities must exist before their incoming edges are materialised.
    for phi in &ssa.phis {
        ensure_value(
            &mut values,
            &mut value_by_ssa,
            &storage_by_register,
            &storages,
            SsaValue {
                base: phi.base.clone(),
                version: phi.dst_version,
            },
            Definition::Phi {
                block: BlockId(phi.block_idx),
                incoming: Vec::new(),
            },
            None,
        );
    }

    for (block_index, block) in llir.blocks.iter().enumerate() {
        for (instruction_index, instruction) in block.instrs.iter().enumerate() {
            let address = InstrAddr {
                block_idx: block_index,
                instr_idx: instruction_index,
            };
            let instruction_id = instruction_ids[block_index][instruction_index];
            for (output_index, ssa_value) in ssa.def_values(llir, address).into_iter().enumerate() {
                let definition = match &instruction.op {
                    Op::Undef { reason, .. } => Definition::Undef {
                        instruction: instruction_id,
                        reason: reason.clone(),
                    },
                    Op::Intrinsic { .. } | Op::Unknown { .. } => Definition::UnknownEffect {
                        instruction: instruction_id,
                        output_index,
                    },
                    _ if !reachable.contains(&BlockId(block_index)) => Definition::Unreachable {
                        block: BlockId(block_index),
                    },
                    _ => Definition::InstructionOutput {
                        instruction: instruction_id,
                        output_index,
                    },
                };
                let id = ensure_value(
                    &mut values,
                    &mut value_by_ssa,
                    &storage_by_register,
                    &storages,
                    ssa_value,
                    definition,
                    output_width(&instruction.op, output_index),
                );
                instructions[instruction_id.0].outputs.push(id);
            }
        }
    }

    for phi in &ssa.phis {
        let destination = value_by_ssa[&SsaValue {
            base: phi.base.clone(),
            version: phi.dst_version,
        }];
        let incoming = phi
            .incoming
            .iter()
            .filter_map(|(block, version)| {
                value_by_ssa
                    .get(&SsaValue {
                        base: phi.base.clone(),
                        version: *version,
                    })
                    .copied()
                    .map(|value| (BlockId(*block), value))
            })
            .collect();
        values[destination.0].definition = Definition::Phi {
            block: BlockId(phi.block_idx),
            incoming,
        };
    }

    let mut unreachable_values = BTreeMap::new();
    for (block_index, block) in llir.blocks.iter().enumerate() {
        let block_id = BlockId(block_index);
        if reachable.contains(&block_id) {
            continue;
        }
        for instruction in &block.instrs {
            for register in defs_uses(&instruction.op).1 {
                let register = canon_gpr_for_target(target, &register);
                let storage = storage_by_register[&register];
                unreachable_values
                    .entry((block_id, storage))
                    .or_insert_with(|| {
                        let id = ValueId(values.len());
                        values.push(MirValue {
                            id,
                            storage,
                            width: storages[storage.0].width,
                            definition: Definition::Unreachable { block: block_id },
                        });
                        id
                    });
            }
        }
    }

    let mut uses = Vec::new();
    for (block_index, block) in llir.blocks.iter().enumerate() {
        for (instruction_index, instruction) in block.instrs.iter().enumerate() {
            let address = InstrAddr {
                block_idx: block_index,
                instr_idx: instruction_index,
            };
            let instruction_id = instruction_ids[block_index][instruction_index];
            for use_index in 0..defs_uses(&instruction.op).1.len() {
                let Some(ssa_value) = ssa.use_value(llir, address, use_index) else {
                    continue;
                };
                let value = if reachable.contains(&BlockId(block_index)) {
                    let Some(&value) = value_by_ssa.get(&ssa_value) else {
                        continue;
                    };
                    value
                } else {
                    let storage = storage_by_register[&ssa_value.base];
                    unreachable_values[&(BlockId(block_index), storage)]
                };
                let storage = values[value.0].storage;
                let id = UseId(uses.len());
                uses.push(MirUse {
                    id,
                    instruction: instruction_id,
                    index: use_index,
                    value,
                    storage,
                    width: values[value.0].width,
                });
                instructions[instruction_id.0].uses.push(id);
            }
        }
    }

    let blocks = llir
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| MirBlock {
            id: BlockId(index),
            start_va: block.start_va,
            end_va: block.end_va,
            predecessors: predecessors[index].clone(),
            successors: block
                .succs
                .iter()
                .filter_map(|successor| va_to_block.get(successor).copied())
                .collect(),
            instructions: instruction_ids[index].clone(),
            reachable: reachable.contains(&BlockId(index)),
        })
        .collect();

    MirFunction {
        target,
        entry: BlockId(0),
        blocks,
        instructions,
        storages,
        values,
        uses,
        memory_values: Vec::new(),
        memory_accesses: Vec::new(),
        object_model: Default::default(),
    }
}

fn ensure_value(
    values: &mut Vec<MirValue>,
    value_by_ssa: &mut BTreeMap<SsaValue, ValueId>,
    storage_by_register: &BTreeMap<VReg, StorageId>,
    storages: &[MirStorage],
    ssa_value: SsaValue,
    definition: Definition,
    width: Option<Width>,
) -> ValueId {
    if let Some(id) = value_by_ssa.get(&ssa_value) {
        return *id;
    }
    let storage = storage_by_register[&ssa_value.base];
    let id = ValueId(values.len());
    values.push(MirValue {
        id,
        storage,
        width: width.or(storages[storage.0].width),
        definition,
    });
    value_by_ssa.insert(ssa_value, id);
    id
}

fn reachable_blocks(llir: &LlirFunction, by_va: &BTreeMap<u64, BlockId>) -> BTreeSet<BlockId> {
    let mut reached = BTreeSet::new();
    if llir.blocks.is_empty() {
        return reached;
    }
    let mut queue = VecDeque::from([BlockId(0)]);
    while let Some(block) = queue.pop_front() {
        if !reached.insert(block) {
            continue;
        }
        for successor in &llir.blocks[block.0].succs {
            if let Some(successor) = by_va.get(successor) {
                queue.push_back(*successor);
            }
        }
    }
    reached
}

fn storage_width(target: TargetSpec, register: &VReg) -> Option<Width> {
    match register {
        VReg::Flag(_) | VReg::FlagValue { .. } => Some(Width::W1),
        VReg::Temp(_) => None,
        VReg::Phys(name) => match target.id() {
            crate::target::TargetId::Arm32 if is_arm32_core_register(name) => Some(Width::W32),
            _ => phys_reg_width(name),
        },
    }
}

fn is_arm32_core_register(name: &str) -> bool {
    matches!(name, "sp" | "lr" | "pc" | "fp")
        || name
            .strip_prefix('r')
            .and_then(|index| index.parse::<u8>().ok())
            .is_some_and(|index| index <= 15)
}

fn output_width(op: &Op, output_index: usize) -> Option<Width> {
    match op {
        Op::Cmp { .. } => Some(Width::W1),
        Op::Load { addr, .. } | Op::CondLoad { addr, .. } => {
            Some(Width::from_bytes(addr.size as u16))
        }
        Op::ZExt { to, .. } | Op::SExt { to, .. } | Op::Trunc { to, .. } => Some(*to),
        Op::Extract { hi, lo, .. } => Some(Width(hi.saturating_sub(*lo))),
        Op::Ite { width, .. } => Some(*width),
        Op::Intrinsic { outs, .. } => outs.get(output_index).map(|(_, width)| *width),
        _ => None,
    }
}
