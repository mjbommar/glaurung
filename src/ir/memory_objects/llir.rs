//! LLIR and MemorySSA adapter for common memory-object access evidence.

use crate::ir::memory_objects::{AccessRole, AccessSource, MemoryObjectBuilder, MemoryObjectModel};
use crate::ir::memory_ssa::{MemorySsaError, MemorySsaInfo};
use crate::ir::types::{LlirFunction, MemOp, Op};
use crate::ir::use_def::InstrAddr;

/// Collect direct affine LLIR accesses with exact instruction and memory-state
/// provenance. Origins and repeated strides remain later MIR constraints, so
/// this adapter intentionally leaves those conflicts explicit.
pub(crate) fn infer_from_llir(
    function: &LlirFunction,
    memory: &MemorySsaInfo,
) -> Result<MemoryObjectModel, MemorySsaError> {
    memory.verify(function)?;
    let mut builder = MemoryObjectBuilder::default();
    for (block_idx, block) in function.blocks.iter().enumerate() {
        for (instr_idx, instruction) in block.instrs.iter().enumerate() {
            let address = InstrAddr {
                block_idx,
                instr_idx,
            };
            match &instruction.op {
                Op::Load { addr, .. } | Op::CondLoad { addr, .. } => {
                    observe_memop(&mut builder, addr, AccessRole::Read, address, memory);
                }
                Op::Store { addr, .. } | Op::CondStore { addr, .. } => {
                    observe_memop(&mut builder, addr, AccessRole::Write, address, memory);
                }
                _ => {}
            }
        }
    }
    Ok(builder.finish())
}

fn observe_memop(
    builder: &mut MemoryObjectBuilder,
    memop: &MemOp,
    role: AccessRole,
    address: InstrAddr,
    memory: &MemorySsaInfo,
) {
    let (Some(base), None, None) = (&memop.base, &memop.index, &memop.segment) else {
        return;
    };
    let memory_version = memory.access_at(address).and_then(|access| match role {
        AccessRole::Read => Some(access.input),
        AccessRole::Write => access.output,
    });
    builder.observe_access(
        base.clone(),
        memop.disp,
        memop.size,
        role,
        AccessSource::LlirInstruction(address),
        memory_version,
    );
}
