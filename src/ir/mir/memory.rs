//! Image-qualified MemorySSA projection into stable MIR identities.

use std::collections::BTreeMap;

use crate::ir::memory_ssa::{
    compute_memory_ssa, MemoryAccess as SourceMemoryAccess, MemoryRegion, MemorySsaInfo,
    MemoryVersionId as SourceMemoryVersionId,
};
use crate::ir::types::LlirFunction;
use crate::ir::use_def::InstrAddr;
use crate::program::image::ProgramImage;

use super::builder::lower;
use super::model::{
    BlockId, MemoryAccessId, MemoryDefinition, MemoryValueId, MirFunction, MirMemoryAccess,
    MirMemoryValue,
};
use super::verify::verify;

/// Lower LLIR and attach independently verified, image-qualified memory SSA.
pub fn lower_verified_with_image(
    llir: &LlirFunction,
    image: &ProgramImage,
) -> Result<MirFunction, Vec<String>> {
    if llir.blocks.is_empty() {
        return Err(vec!["LLIR function has no blocks".to_string()]);
    }
    let memory = compute_memory_ssa(llir, image);
    memory
        .verify(llir, image)
        .map_err(|error| vec![error.to_string()])?;
    let mut mir = lower(llir, *image.target());
    attach_memory(&mut mir, llir, &memory);
    let errors = verify(&mir);
    if errors.is_empty() {
        Ok(mir)
    } else {
        Err(errors)
    }
}

fn attach_memory(mir: &mut MirFunction, llir: &LlirFunction, memory: &MemorySsaInfo) {
    let mut source_accesses = Vec::<(InstrAddr, SourceMemoryAccess)>::new();
    for (block_idx, block) in llir.blocks.iter().enumerate() {
        for instr_idx in 0..block.instrs.len() {
            let address = InstrAddr {
                block_idx,
                instr_idx,
            };
            source_accesses.extend(memory.accesses_at(address).map(|access| (address, *access)));
        }
    }

    let access_ids = source_accesses
        .iter()
        .enumerate()
        .map(|(index, (address, access))| ((*address, access.region), MemoryAccessId(index)))
        .collect::<BTreeMap<_, _>>();

    let mut regions = BTreeMap::<SourceMemoryVersionId, MemoryRegion>::new();
    for region in MemoryRegion::ALL {
        regions.insert(SourceMemoryVersionId::entry(region), region);
    }
    for phi in memory.phis() {
        regions.insert(phi.version, phi.region);
    }
    for (_, access) in &source_accesses {
        if let Some(output) = access.output {
            regions.insert(output, access.region);
        }
    }
    let value_ids = regions
        .keys()
        .enumerate()
        .map(|(index, version)| (*version, MemoryValueId(index)))
        .collect::<BTreeMap<_, _>>();

    let phi_by_version = memory
        .phis()
        .iter()
        .map(|phi| (phi.version, phi))
        .collect::<BTreeMap<_, _>>();
    let output_owner = source_accesses
        .iter()
        .filter_map(|(address, access)| {
            access
                .output
                .map(|output| (output, access_ids[&(*address, access.region)]))
        })
        .collect::<BTreeMap<_, _>>();

    mir.memory_values = regions
        .iter()
        .map(|(version, source_region)| {
            let id = value_ids[version];
            let region = *source_region;
            let definition = if *version == SourceMemoryVersionId::entry(*source_region) {
                MemoryDefinition::Entry { region }
            } else if let Some(phi) = phi_by_version.get(version) {
                MemoryDefinition::Phi {
                    block: BlockId(phi.block_idx),
                    region,
                    incoming: phi
                        .incoming
                        .iter()
                        .map(|incoming| {
                            (
                                incoming.predecessor.map(BlockId),
                                value_ids[&incoming.version],
                            )
                        })
                        .collect(),
                }
            } else {
                MemoryDefinition::InstructionOutput {
                    access: output_owner[version],
                }
            };
            MirMemoryValue {
                id,
                region,
                definition,
            }
        })
        .collect();

    mir.memory_accesses = source_accesses
        .iter()
        .enumerate()
        .map(|(index, (address, access))| {
            let id = MemoryAccessId(index);
            let instruction = mir.blocks[address.block_idx].instructions[address.instr_idx];
            mir.instructions[instruction.0].memory_effects.push(id);
            MirMemoryAccess {
                id,
                instruction,
                region: access.region,
                kind: access.kind,
                input: value_ids[&access.input],
                output: access.output.map(|output| value_ids[&output]),
            }
        })
        .collect();
}
