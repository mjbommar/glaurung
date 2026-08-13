//! Structural verification for MIR construction and mutation boundaries.

use std::collections::BTreeSet;

use super::model::{Definition, MemoryDefinition, MirFunction};

pub fn verify(function: &MirFunction) -> Vec<String> {
    let mut errors = Vec::new();
    if function.blocks.is_empty() {
        errors.push("function has no entry block".to_string());
        return errors;
    }
    if function.entry.0 >= function.blocks.len() {
        errors.push("entry block is out of bounds".to_string());
    }
    for (index, storage) in function.storages.iter().enumerate() {
        if storage.id.0 != index {
            errors.push(format!(
                "storage id {} does not match arena index {index}",
                storage.id.0
            ));
        }
    }
    for (index, block) in function.blocks.iter().enumerate() {
        if block.id.0 != index {
            errors.push(format!(
                "block id {} does not match arena index {index}",
                block.id.0
            ));
        }
        for successor in &block.successors {
            if successor.0 >= function.blocks.len() {
                errors.push(format!(
                    "block {index} has invalid successor {}",
                    successor.0
                ));
            } else if !function.blocks[successor.0]
                .predecessors
                .contains(&block.id)
            {
                errors.push(format!("edge {index} -> {} is not reciprocal", successor.0));
            }
        }
        for predecessor in &block.predecessors {
            if predecessor.0 >= function.blocks.len() {
                errors.push(format!(
                    "block {index} has invalid predecessor {}",
                    predecessor.0
                ));
            } else if !function.blocks[predecessor.0]
                .successors
                .contains(&block.id)
            {
                errors.push(format!(
                    "edge {} -> {index} is not reciprocal",
                    predecessor.0
                ));
            }
        }
        for (position, instruction) in block.instructions.iter().enumerate() {
            if instruction.0 >= function.instructions.len() {
                errors.push(format!(
                    "block {index} has invalid instruction {}",
                    instruction.0
                ));
                continue;
            }
            let record = &function.instructions[instruction.0];
            if record.block != block.id || record.index != position {
                errors.push(format!(
                    "block {index} instruction position {position} is inconsistent"
                ));
            }
        }
    }
    for (index, instruction) in function.instructions.iter().enumerate() {
        if instruction.id.0 != index {
            errors.push(format!(
                "instruction id {} does not match arena index {index}",
                instruction.id.0
            ));
        }
        if instruction.block.0 >= function.blocks.len()
            || !function.blocks[instruction.block.0]
                .instructions
                .contains(&instruction.id)
        {
            errors.push(format!("instruction {index} is not owned by its block"));
        }
        for (output_index, value) in instruction.outputs.iter().enumerate() {
            if value.0 >= function.values.len() {
                errors.push(format!(
                    "instruction {index} has invalid output {}",
                    value.0
                ));
                continue;
            }
            match &function.values[value.0].definition {
                Definition::InstructionOutput { instruction: owner, output_index: slot }
                | Definition::UnknownEffect { instruction: owner, output_index: slot }
                    if *owner == instruction.id && *slot == output_index => {}
                Definition::Undef { instruction: owner, .. } if *owner == instruction.id => {}
                Definition::Unreachable { block } if *block == instruction.block => {}
                other => errors.push(format!(
                    "instruction {index} output {output_index} has inconsistent definition {other:?}"
                )),
            }
        }
        let mut seen_memory_regions = BTreeSet::new();
        for access in &instruction.memory_effects {
            if access.0 >= function.memory_accesses.len() {
                errors.push(format!(
                    "instruction {index} has invalid memory access {}",
                    access.0
                ));
                continue;
            }
            let record = &function.memory_accesses[access.0];
            if record.instruction != instruction.id {
                errors.push(format!(
                    "instruction {index} does not own memory access {}",
                    access.0
                ));
            }
            if !seen_memory_regions.insert(record.region) {
                errors.push(format!(
                    "instruction {index} has duplicate {:?} memory effects",
                    record.region
                ));
            }
        }
    }
    for (index, value) in function.values.iter().enumerate() {
        if value.id.0 != index {
            errors.push(format!(
                "value id {} does not match arena index {index}",
                value.id.0
            ));
        }
        if value.storage.0 >= function.storages.len() {
            errors.push(format!(
                "value {index} has invalid storage {}",
                value.storage.0
            ));
        }
        match &value.definition {
            Definition::InstructionOutput {
                instruction,
                output_index,
            }
            | Definition::UnknownEffect {
                instruction,
                output_index,
            } => {
                if function
                    .instructions
                    .get(instruction.0)
                    .and_then(|owner| owner.outputs.get(*output_index))
                    != Some(&value.id)
                {
                    errors.push(format!(
                        "value {index} is orphaned from its defining output"
                    ));
                }
            }
            Definition::Undef { instruction, .. } => {
                if function
                    .instructions
                    .get(instruction.0)
                    .is_none_or(|owner| !owner.outputs.contains(&value.id))
                {
                    errors.push(format!("value {index} is orphaned from its undef output"));
                }
            }
            _ => {}
        }
        if let Definition::Phi { block, incoming } = &value.definition {
            if block.0 >= function.blocks.len() {
                errors.push(format!("value {index} phi has invalid block {}", block.0));
                continue;
            }
            let expected: BTreeSet<_> = function.blocks[block.0]
                .predecessors
                .iter()
                .copied()
                .collect();
            let actual: BTreeSet<_> = incoming
                .iter()
                .map(|(predecessor, _)| *predecessor)
                .collect();
            if actual != expected {
                errors.push(format!(
                    "value {index} phi predecessor set does not match CFG"
                ));
            }
            for (_, incoming_value) in incoming {
                if incoming_value.0 >= function.values.len() {
                    errors.push(format!(
                        "value {index} phi has invalid incoming value {}",
                        incoming_value.0
                    ));
                } else if function.values[incoming_value.0].storage != value.storage {
                    errors.push(format!(
                        "value {index} phi has an incoming storage mismatch"
                    ));
                }
            }
        }
    }
    let dominators = compute_dominators(function);
    for (index, use_) in function.uses.iter().enumerate() {
        if use_.id.0 != index {
            errors.push(format!(
                "use id {} does not match arena index {index}",
                use_.id.0
            ));
        }
        if use_.instruction.0 >= function.instructions.len()
            || !function.instructions[use_.instruction.0]
                .uses
                .contains(&use_.id)
        {
            errors.push(format!("use {index} is not owned by its instruction"));
        } else if function.instructions[use_.instruction.0]
            .uses
            .get(use_.index)
            != Some(&use_.id)
        {
            errors.push(format!("use {index} has an inconsistent operand index"));
        }
        if use_.value.0 >= function.values.len() {
            errors.push(format!("use {index} has invalid value {}", use_.value.0));
        } else if function.values[use_.value.0].storage != use_.storage {
            errors.push(format!("use {index} has a value/storage mismatch"));
        } else if !definition_dominates_use(function, &dominators, use_.value.0, index) {
            errors.push(format!(
                "use {index} reaching value does not dominate the use"
            ));
        }
    }
    for (index, value) in function.memory_values.iter().enumerate() {
        if value.id.0 != index {
            errors.push(format!(
                "memory value id {} does not match arena index {index}",
                value.id.0
            ));
        }
        match &value.definition {
            MemoryDefinition::Entry { region } => {
                if *region != value.region {
                    errors.push(format!("memory value {index} entry region mismatch"));
                }
            }
            MemoryDefinition::InstructionOutput { access } => {
                if function.memory_accesses.get(access.0).is_none_or(|owner| {
                    owner.output != Some(value.id) || owner.region != value.region
                }) {
                    errors.push(format!(
                        "memory value {index} is orphaned from its defining access"
                    ));
                }
            }
            MemoryDefinition::Phi {
                block,
                region,
                incoming,
            } => {
                if *region != value.region {
                    errors.push(format!("memory value {index} phi region mismatch"));
                }
                if block.0 >= function.blocks.len() {
                    errors.push(format!(
                        "memory value {index} phi has invalid block {}",
                        block.0
                    ));
                    continue;
                }
                let mut expected = function.blocks[block.0]
                    .predecessors
                    .iter()
                    .copied()
                    .map(Some)
                    .collect::<BTreeSet<_>>();
                if *block == function.entry {
                    expected.insert(None);
                }
                let actual = incoming
                    .iter()
                    .map(|(predecessor, _)| *predecessor)
                    .collect::<BTreeSet<_>>();
                if actual != expected || actual.len() != incoming.len() {
                    errors.push(format!(
                        "memory value {index} phi predecessor set does not match CFG"
                    ));
                }
                for (_, incoming_value) in incoming {
                    if function
                        .memory_values
                        .get(incoming_value.0)
                        .is_none_or(|incoming| incoming.region != value.region)
                    {
                        errors.push(format!(
                            "memory value {index} phi has an incoming region mismatch"
                        ));
                    }
                }
            }
        }
    }
    for (index, access) in function.memory_accesses.iter().enumerate() {
        if access.id.0 != index {
            errors.push(format!(
                "memory access id {} does not match arena index {index}",
                access.id.0
            ));
        }
        if function
            .instructions
            .get(access.instruction.0)
            .is_none_or(|owner| !owner.memory_effects.contains(&access.id))
        {
            errors.push(format!(
                "memory access {index} is not owned by its instruction"
            ));
        }
        let Some(input) = function.memory_values.get(access.input.0) else {
            errors.push(format!(
                "memory access {index} has invalid input {}",
                access.input.0
            ));
            continue;
        };
        if input.region != access.region {
            errors.push(format!("memory access {index} memory region mismatch"));
        }
        if !memory_definition_dominates_access(function, &dominators, access.input.0, index) {
            errors.push(format!(
                "memory access {index} reaching state does not dominate the access"
            ));
        }
        if access.kind.writes() != access.output.is_some() {
            errors.push(format!(
                "memory access {index} definition presence mismatch"
            ));
        }
        if let Some(output) = access.output {
            if function.memory_values.get(output.0).is_none_or(|value| {
                value.region != access.region
                    || value.definition
                        != (MemoryDefinition::InstructionOutput { access: access.id })
            }) {
                errors.push(format!(
                    "memory access {index} has an inconsistent output definition"
                ));
            }
        }
    }
    errors
}

fn compute_dominators(function: &MirFunction) -> Vec<BTreeSet<usize>> {
    let reachable: BTreeSet<_> = function
        .blocks
        .iter()
        .filter(|block| block.reachable)
        .map(|block| block.id.0)
        .collect();
    let mut dominators = vec![BTreeSet::new(); function.blocks.len()];
    for block in &function.blocks {
        if block.reachable {
            dominators[block.id.0] = if block.id == function.entry {
                BTreeSet::from([block.id.0])
            } else {
                reachable.clone()
            };
        }
    }
    let mut changed = true;
    while changed {
        changed = false;
        for block in function
            .blocks
            .iter()
            .filter(|block| block.reachable && block.id != function.entry)
        {
            let mut incoming = block
                .predecessors
                .iter()
                .filter(|predecessor| function.blocks[predecessor.0].reachable)
                .map(|predecessor| dominators[predecessor.0].clone());
            let mut next = incoming.next().unwrap_or_default();
            for predecessor_dominators in incoming {
                next = next
                    .intersection(&predecessor_dominators)
                    .copied()
                    .collect();
            }
            next.insert(block.id.0);
            if next != dominators[block.id.0] {
                dominators[block.id.0] = next;
                changed = true;
            }
        }
    }
    dominators
}

fn definition_dominates_use(
    function: &MirFunction,
    dominators: &[BTreeSet<usize>],
    value_index: usize,
    use_index: usize,
) -> bool {
    let use_ = &function.uses[use_index];
    let use_instruction = &function.instructions[use_.instruction.0];
    let definition = &function.values[value_index].definition;
    match definition {
        Definition::Input => true,
        Definition::Phi { block, .. } => {
            *block == use_instruction.block
                || dominators[use_instruction.block.0].contains(&block.0)
        }
        Definition::InstructionOutput { instruction, .. }
        | Definition::Undef { instruction, .. }
        | Definition::UnknownEffect { instruction, .. } => {
            let definition_instruction = &function.instructions[instruction.0];
            if definition_instruction.block == use_instruction.block {
                definition_instruction.index < use_instruction.index
            } else {
                dominators[use_instruction.block.0].contains(&definition_instruction.block.0)
            }
        }
        Definition::Unreachable { block } => {
            !function.blocks[use_instruction.block.0].reachable && *block == use_instruction.block
        }
    }
}

fn memory_definition_dominates_access(
    function: &MirFunction,
    dominators: &[BTreeSet<usize>],
    value_index: usize,
    access_index: usize,
) -> bool {
    let Some(access) = function.memory_accesses.get(access_index) else {
        return false;
    };
    let Some(use_instruction) = function.instructions.get(access.instruction.0) else {
        return false;
    };
    let Some(value) = function.memory_values.get(value_index) else {
        return false;
    };
    match &value.definition {
        MemoryDefinition::Entry { .. } => true,
        MemoryDefinition::Phi { block, .. } => {
            if block.0 >= function.blocks.len() || use_instruction.block.0 >= dominators.len() {
                return false;
            }
            *block == use_instruction.block
                || dominators[use_instruction.block.0].contains(&block.0)
        }
        MemoryDefinition::InstructionOutput { access } => {
            let Some(definition_access) = function.memory_accesses.get(access.0) else {
                return false;
            };
            let Some(definition_instruction) =
                function.instructions.get(definition_access.instruction.0)
            else {
                return false;
            };
            if definition_instruction.block == use_instruction.block {
                definition_instruction.index < use_instruction.index
            } else {
                use_instruction.block.0 < dominators.len()
                    && dominators[use_instruction.block.0].contains(&definition_instruction.block.0)
            }
        }
    }
}
