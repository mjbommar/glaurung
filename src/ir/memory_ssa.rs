//! Conservative memory SSA over LLIR.
//!
//! Register SSA intentionally leaves memory unversioned. Aggregate recovery now
//! needs to distinguish the memory state observed by a load from the state
//! created by a store or call, so this sidecar gives the whole address space one
//! conservative SSA token. Alias regions can split that token later without
//! changing access identities or consumers.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::ir::types::{LlirFunction, Op};
use crate::ir::use_def::InstrAddr;

/// Identity of one reaching memory state within a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct MemoryVersionId(usize);

impl MemoryVersionId {
    /// Memory entering the function, or an unreachable component whose origin
    /// is conservatively unknown.
    pub(crate) const ENTRY: Self = Self(0);
}

/// Alias region owned by one memory token.
///
/// The first implementation deliberately versions all memory together. This
/// is conservative across stack/global/heap aliases and gives later region
/// refinement a typed extension point rather than a name-based special case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum MemoryRegion {
    Unknown,
}

/// Observable memory effect of one LLIR instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum MemoryAccessKind {
    Read,
    Write,
    ReadWrite,
    Clobber,
}

impl MemoryAccessKind {
    fn writes(self) -> bool {
        matches!(self, Self::Write | Self::ReadWrite | Self::Clobber)
    }
}

/// Memory state consumed and optionally produced by one instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MemoryAccess {
    pub(crate) kind: MemoryAccessKind,
    pub(crate) region: MemoryRegion,
    pub(crate) input: MemoryVersionId,
    pub(crate) output: Option<MemoryVersionId>,
}

/// One incoming memory state at a CFG join.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct MemoryIncoming {
    /// `None` is the implicit function-entry edge into a looping entry block.
    pub(crate) predecessor: Option<usize>,
    pub(crate) version: MemoryVersionId,
}

/// Explicit memory phi for one CFG join or looping entry block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MemoryPhi {
    pub(crate) block_idx: usize,
    pub(crate) version: MemoryVersionId,
    pub(crate) incoming: Vec<MemoryIncoming>,
}

/// A verifier failure in a constructed memory-SSA sidecar.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("memory SSA invariant failed: {message}")]
pub(crate) struct MemorySsaError {
    message: String,
}

impl MemorySsaError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Deterministic memory definitions, uses, and phis for one LLIR function.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct MemorySsaInfo {
    entry_versions: Vec<MemoryVersionId>,
    exit_versions: Vec<MemoryVersionId>,
    accesses: BTreeMap<InstrAddr, MemoryAccess>,
    phis: Vec<MemoryPhi>,
}

impl MemorySsaInfo {
    pub(crate) fn access_at(&self, address: InstrAddr) -> Option<&MemoryAccess> {
        self.accesses.get(&address)
    }

    pub(crate) fn entry_version(&self, block_idx: usize) -> Option<MemoryVersionId> {
        self.entry_versions.get(block_idx).copied()
    }

    pub(crate) fn exit_version(&self, block_idx: usize) -> Option<MemoryVersionId> {
        self.exit_versions.get(block_idx).copied()
    }

    pub(crate) fn phi_for_block(&self, block_idx: usize) -> Option<&MemoryPhi> {
        self.phis.iter().find(|phi| phi.block_idx == block_idx)
    }

    /// Recheck CFG shape, effect coverage, state threading, version ownership,
    /// and phi inputs independently of the builder.
    pub(crate) fn verify(&self, function: &LlirFunction) -> Result<(), MemorySsaError> {
        if self.entry_versions.len() != function.blocks.len()
            || self.exit_versions.len() != function.blocks.len()
        {
            return Err(MemorySsaError::new("block state vector length mismatch"));
        }

        let expected_access_count = function
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .filter(|instruction| memory_effect(&instruction.op).is_some())
            .count();
        if self.accesses.len() != expected_access_count {
            return Err(MemorySsaError::new("memory access record count mismatch"));
        }

        let predecessors = build_predecessors(function);
        let expected_phi_count = predecessors
            .iter()
            .enumerate()
            .filter(|(block_idx, block_predecessors)| {
                (*block_idx == 0 && !block_predecessors.is_empty()) || block_predecessors.len() > 1
            })
            .count();
        if self.phis.len() != expected_phi_count {
            return Err(MemorySsaError::new("memory phi record count mismatch"));
        }
        let mut definitions = BTreeSet::from([MemoryVersionId::ENTRY]);
        let mut phi_blocks = BTreeSet::new();
        for phi in &self.phis {
            if phi.block_idx >= function.blocks.len()
                || !phi_blocks.insert(phi.block_idx)
                || !definitions.insert(phi.version)
            {
                return Err(MemorySsaError::new("invalid or duplicate phi definition"));
            }
        }
        for access in self.accesses.values() {
            if let Some(output) = access.output {
                if !definitions.insert(output) {
                    return Err(MemorySsaError::new("duplicate memory definition"));
                }
            }
        }
        for access in self.accesses.values() {
            if !definitions.contains(&access.input)
                || access
                    .output
                    .is_some_and(|output| !definitions.contains(&output))
            {
                return Err(MemorySsaError::new("access references an unknown version"));
            }
        }

        for (block_idx, block) in function.blocks.iter().enumerate() {
            let expected_phi = block_idx == 0 && !predecessors[block_idx].is_empty()
                || predecessors[block_idx].len() > 1;
            let phi = self.phi_for_block(block_idx);
            if expected_phi != phi.is_some() {
                return Err(MemorySsaError::new(format!(
                    "block {block_idx} phi presence mismatch"
                )));
            }
            if let Some(phi) = phi {
                if self.entry_version(block_idx) != Some(phi.version) {
                    return Err(MemorySsaError::new(format!(
                        "block {block_idx} phi is not its entry state"
                    )));
                }
                let mut expected = predecessors[block_idx]
                    .iter()
                    .map(|predecessor| {
                        self.exit_version(*predecessor)
                            .map(|version| MemoryIncoming {
                                predecessor: Some(*predecessor),
                                version,
                            })
                            .ok_or_else(|| MemorySsaError::new("predecessor state is missing"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if block_idx == 0 {
                    expected.push(MemoryIncoming {
                        predecessor: None,
                        version: MemoryVersionId::ENTRY,
                    });
                }
                expected.sort();
                if phi.incoming != expected {
                    return Err(MemorySsaError::new(format!(
                        "block {block_idx} phi inputs mismatch"
                    )));
                }
            }

            let mut current = self
                .entry_version(block_idx)
                .ok_or_else(|| MemorySsaError::new("block entry state is missing"))?;
            for (instr_idx, instruction) in block.instrs.iter().enumerate() {
                let address = InstrAddr {
                    block_idx,
                    instr_idx,
                };
                let expected_kind = memory_effect(&instruction.op);
                let access = self.access_at(address);
                if expected_kind.is_some() != access.is_some() {
                    return Err(MemorySsaError::new(format!(
                        "instruction {address:?} effect coverage mismatch"
                    )));
                }
                let Some(kind) = expected_kind else {
                    continue;
                };
                let Some(access) = access else {
                    return Err(MemorySsaError::new(format!(
                        "instruction {address:?} memory effect is missing"
                    )));
                };
                if access.kind != kind || access.input != current {
                    return Err(MemorySsaError::new(format!(
                        "instruction {address:?} memory state mismatch"
                    )));
                }
                if kind.writes() != access.output.is_some() {
                    return Err(MemorySsaError::new(format!(
                        "instruction {address:?} definition presence mismatch"
                    )));
                }
                if let Some(output) = access.output {
                    current = output;
                }
            }
            if self.exit_version(block_idx) != Some(current) {
                return Err(MemorySsaError::new(format!(
                    "block {block_idx} exit state mismatch"
                )));
            }
        }
        Ok(())
    }
}

/// Compute a one-region, conservative MemorySSA sidecar.
pub(crate) fn compute_memory_ssa(function: &LlirFunction) -> MemorySsaInfo {
    let predecessors = build_predecessors(function);
    let block_count = function.blocks.len();
    let mut next_version = 1usize;
    let mut phi_versions = vec![None; block_count];
    for block_idx in 0..block_count {
        if block_idx == 0 && !predecessors[block_idx].is_empty()
            || predecessors[block_idx].len() > 1
        {
            phi_versions[block_idx] = Some(MemoryVersionId(next_version));
            next_version = next_version.saturating_add(1);
        }
    }

    let mut outputs = BTreeMap::new();
    let mut last_definition = vec![None; block_count];
    for (block_idx, block) in function.blocks.iter().enumerate() {
        for (instr_idx, instruction) in block.instrs.iter().enumerate() {
            if memory_effect(&instruction.op).is_some_and(MemoryAccessKind::writes) {
                let version = MemoryVersionId(next_version);
                next_version = next_version.saturating_add(1);
                let address = InstrAddr {
                    block_idx,
                    instr_idx,
                };
                outputs.insert(address, version);
                last_definition[block_idx] = Some(version);
            }
        }
    }

    let mut entry_versions = vec![None; block_count];
    let mut exit_versions = vec![None; block_count];
    for block_idx in 0..block_count {
        entry_versions[block_idx] = phi_versions[block_idx].or_else(|| {
            (block_idx == 0 || predecessors[block_idx].is_empty()).then_some(MemoryVersionId::ENTRY)
        });
        exit_versions[block_idx] = last_definition[block_idx];
    }
    resolve_block_states(
        &predecessors,
        &last_definition,
        &mut entry_versions,
        &mut exit_versions,
    );
    for block_idx in 0..block_count {
        entry_versions[block_idx].get_or_insert(MemoryVersionId::ENTRY);
        let entry_version = entry_versions[block_idx].unwrap_or(MemoryVersionId::ENTRY);
        exit_versions[block_idx].get_or_insert(last_definition[block_idx].unwrap_or(entry_version));
    }
    resolve_block_states(
        &predecessors,
        &last_definition,
        &mut entry_versions,
        &mut exit_versions,
    );
    let entry_versions = entry_versions
        .into_iter()
        .map(|version| version.unwrap_or(MemoryVersionId::ENTRY))
        .collect::<Vec<_>>();
    let exit_versions = exit_versions
        .into_iter()
        .map(|version| version.unwrap_or(MemoryVersionId::ENTRY))
        .collect::<Vec<_>>();

    let mut accesses = BTreeMap::new();
    for (block_idx, block) in function.blocks.iter().enumerate() {
        let mut current = entry_versions[block_idx];
        for (instr_idx, instruction) in block.instrs.iter().enumerate() {
            let Some(kind) = memory_effect(&instruction.op) else {
                continue;
            };
            let address = InstrAddr {
                block_idx,
                instr_idx,
            };
            let output = outputs.get(&address).copied();
            accesses.insert(
                address,
                MemoryAccess {
                    kind,
                    region: MemoryRegion::Unknown,
                    input: current,
                    output,
                },
            );
            if let Some(output) = output {
                current = output;
            }
        }
    }

    let mut phis = phi_versions
        .into_iter()
        .enumerate()
        .filter_map(|(block_idx, version)| {
            version.map(|version| {
                let mut incoming = predecessors[block_idx]
                    .iter()
                    .map(|predecessor| MemoryIncoming {
                        predecessor: Some(*predecessor),
                        version: exit_versions[*predecessor],
                    })
                    .collect::<Vec<_>>();
                if block_idx == 0 {
                    incoming.push(MemoryIncoming {
                        predecessor: None,
                        version: MemoryVersionId::ENTRY,
                    });
                }
                incoming.sort();
                MemoryPhi {
                    block_idx,
                    version,
                    incoming,
                }
            })
        })
        .collect::<Vec<_>>();
    phis.sort_by_key(|phi| phi.block_idx);

    MemorySsaInfo {
        entry_versions,
        exit_versions,
        accesses,
        phis,
    }
}

fn resolve_block_states(
    predecessors: &[Vec<usize>],
    last_definition: &[Option<MemoryVersionId>],
    entry_versions: &mut [Option<MemoryVersionId>],
    exit_versions: &mut [Option<MemoryVersionId>],
) {
    for _ in 0..=predecessors.len() {
        let mut changed = false;
        for block_idx in 0..predecessors.len() {
            if entry_versions[block_idx].is_none() && predecessors[block_idx].len() == 1 {
                let predecessor = predecessors[block_idx][0];
                if let Some(version) = exit_versions[predecessor] {
                    entry_versions[block_idx] = Some(version);
                    changed = true;
                }
            }
            if exit_versions[block_idx].is_none() {
                if let Some(version) = last_definition[block_idx].or(entry_versions[block_idx]) {
                    exit_versions[block_idx] = Some(version);
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
}

fn build_predecessors(function: &LlirFunction) -> Vec<Vec<usize>> {
    let by_va = function
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start_va, index))
        .collect::<HashMap<_, _>>();
    let mut predecessors = vec![Vec::new(); function.blocks.len()];
    for (block_idx, block) in function.blocks.iter().enumerate() {
        for successor in &block.succs {
            if let Some(successor_idx) = by_va.get(successor).copied() {
                predecessors[successor_idx].push(block_idx);
            }
        }
    }
    for block_predecessors in &mut predecessors {
        block_predecessors.sort_unstable();
        block_predecessors.dedup();
    }
    predecessors
}

fn memory_effect(op: &Op) -> Option<MemoryAccessKind> {
    match op {
        Op::Load { .. } | Op::CondLoad { .. } => Some(MemoryAccessKind::Read),
        Op::Store { .. } | Op::CondStore { .. } => Some(MemoryAccessKind::Write),
        Op::Call { .. } | Op::Unknown { .. } => Some(MemoryAccessKind::Clobber),
        Op::Intrinsic {
            reads_mem,
            writes_mem,
            ..
        } => match (*reads_mem, *writes_mem) {
            (false, false) => None,
            (true, false) => Some(MemoryAccessKind::Read),
            (false, true) => Some(MemoryAccessKind::Write),
            (true, true) => Some(MemoryAccessKind::ReadWrite),
        },
        _ => None,
    }
}

#[cfg(test)]
#[path = "memory_ssa_tests.rs"]
mod tests;
