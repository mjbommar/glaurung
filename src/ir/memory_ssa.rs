//! Conservative target-backed memory SSA over LLIR.
//!
//! Register SSA intentionally leaves memory unversioned. This sidecar tracks
//! five architecture-qualified memory regions while preserving conservative
//! may-alias behavior: exact stack and mapped-image addresses use their proven
//! regions, arbitrary pointers touch every region they may alias, and calls or
//! opaque effects clobber every mutable region.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::ir::types::{LlirFunction, MemOp, Op, VReg};
use crate::ir::use_def::InstrAddr;
use crate::program::image::{ImageMemoryKind, ProgramImage};

/// Identity of one reaching memory state within a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct MemoryVersionId(usize);

impl MemoryVersionId {
    /// Region-specific memory entering the function.
    pub(crate) const fn entry(region: MemoryRegion) -> Self {
        Self(region as usize)
    }
}

/// Conservative alias regions shared by MemorySSA and memory-object recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum MemoryRegion {
    /// Proven stack/frame-coordinate memory.
    Stack,
    /// Proven writable storage mapped by the program image.
    KnownGlobal,
    /// Proven non-writable storage mapped by the program image.
    ReadOnlyImage,
    /// Pointer-based memory without a more precise proven origin.
    HeapUnknown,
    /// Umbrella state for effects whose address footprint is itself unknown.
    FullyUnknown,
}

impl MemoryRegion {
    pub(crate) const ALL: [Self; 5] = [
        Self::Stack,
        Self::KnownGlobal,
        Self::ReadOnlyImage,
        Self::HeapUnknown,
        Self::FullyUnknown,
    ];

    fn mutable(self) -> bool {
        !matches!(self, Self::ReadOnlyImage)
    }
}

/// Observable memory effect of one LLIR instruction in one region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemoryAccessKind {
    Read,
    Write,
    Clobber,
}

impl MemoryAccessKind {
    pub(crate) fn writes(self) -> bool {
        matches!(self, Self::Write | Self::Clobber)
    }
}

/// Memory state consumed and optionally produced by one instruction/region.
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

/// Explicit memory phi for one region at one CFG join.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MemoryPhi {
    pub(crate) block_idx: usize,
    pub(crate) region: MemoryRegion,
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

type BlockRegion = (usize, MemoryRegion);
type AccessKey = (InstrAddr, MemoryRegion);

/// Deterministic memory definitions, uses, and phis for one LLIR function.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct MemorySsaInfo {
    entry_versions: BTreeMap<BlockRegion, MemoryVersionId>,
    exit_versions: BTreeMap<BlockRegion, MemoryVersionId>,
    pub(super) accesses: BTreeMap<AccessKey, MemoryAccess>,
    phis: Vec<MemoryPhi>,
}

impl MemorySsaInfo {
    pub(crate) fn access_at(
        &self,
        address: InstrAddr,
        region: MemoryRegion,
    ) -> Option<&MemoryAccess> {
        self.accesses.get(&(address, region))
    }

    pub(crate) fn accesses_at(&self, address: InstrAddr) -> impl Iterator<Item = &MemoryAccess> {
        self.accesses
            .range((address, MemoryRegion::Stack)..=(address, MemoryRegion::FullyUnknown))
            .map(|(_, access)| access)
    }

    pub(crate) fn entry_version(
        &self,
        block_idx: usize,
        region: MemoryRegion,
    ) -> Option<MemoryVersionId> {
        self.entry_versions.get(&(block_idx, region)).copied()
    }

    pub(crate) fn exit_version(
        &self,
        block_idx: usize,
        region: MemoryRegion,
    ) -> Option<MemoryVersionId> {
        self.exit_versions.get(&(block_idx, region)).copied()
    }

    pub(crate) fn phi_for_block(
        &self,
        block_idx: usize,
        region: MemoryRegion,
    ) -> Option<&MemoryPhi> {
        self.phis
            .iter()
            .find(|phi| phi.block_idx == block_idx && phi.region == region)
    }

    pub(crate) fn phis(&self) -> &[MemoryPhi] {
        &self.phis
    }

    /// Recheck target classification, CFG shape, exact effect coverage, state
    /// threading, version ownership, and phi inputs independently of the builder.
    pub(crate) fn verify(
        &self,
        function: &LlirFunction,
        image: &ProgramImage,
    ) -> Result<(), MemorySsaError> {
        let expected_state_count = function.blocks.len() * MemoryRegion::ALL.len();
        if self.entry_versions.len() != expected_state_count
            || self.exit_versions.len() != expected_state_count
        {
            return Err(MemorySsaError::new("block/region state count mismatch"));
        }

        let expected_accesses = expected_accesses(function, image);
        if self.accesses.len() != expected_accesses.len()
            || self.accesses.keys().ne(expected_accesses.keys())
        {
            return Err(MemorySsaError::new("memory access key coverage mismatch"));
        }
        for (block_idx, block) in function.blocks.iter().enumerate() {
            for instr_idx in 0..block.instrs.len() {
                let address = InstrAddr {
                    block_idx,
                    instr_idx,
                };
                let expected_count = MemoryRegion::ALL
                    .iter()
                    .filter(|region| expected_accesses.contains_key(&(address, **region)))
                    .count();
                if self.accesses_at(address).count() != expected_count {
                    return Err(MemorySsaError::new(format!(
                        "instruction {address:?} memory effect cardinality mismatch"
                    )));
                }
            }
        }

        let predecessors = build_predecessors(function);
        let join_count = predecessors
            .iter()
            .enumerate()
            .filter(|(block_idx, incoming)| {
                (*block_idx == 0 && !incoming.is_empty()) || incoming.len() > 1
            })
            .count();
        if self.phis.len() != join_count * MemoryRegion::ALL.len() {
            return Err(MemorySsaError::new("memory phi record count mismatch"));
        }

        let mut definitions = BTreeMap::new();
        for region in MemoryRegion::ALL {
            definitions.insert(MemoryVersionId::entry(region), region);
        }
        let mut phi_keys = BTreeSet::new();
        for phi in &self.phis {
            if phi.block_idx >= function.blocks.len()
                || !phi_keys.insert((phi.block_idx, phi.region))
                || definitions.insert(phi.version, phi.region).is_some()
            {
                return Err(MemorySsaError::new("invalid or duplicate phi definition"));
            }
        }
        for ((_, key_region), access) in &self.accesses {
            if access.region != *key_region {
                return Err(MemorySsaError::new("access key/region mismatch"));
            }
            if let Some(output) = access.output {
                if definitions.insert(output, access.region).is_some() {
                    return Err(MemorySsaError::new("duplicate memory definition"));
                }
            }
        }
        for ((key, region), access) in &self.accesses {
            if expected_accesses.get(&(*key, *region)) != Some(&access.kind) {
                return Err(MemorySsaError::new(format!(
                    "instruction {key:?} region {region:?} effect mismatch"
                )));
            }
            if definitions.get(&access.input) != Some(region)
                || access
                    .output
                    .is_some_and(|output| definitions.get(&output) != Some(region))
            {
                return Err(MemorySsaError::new("access crosses memory-region versions"));
            }
            if access.kind.writes() != access.output.is_some() {
                return Err(MemorySsaError::new("memory definition presence mismatch"));
            }
        }

        for (block_idx, block) in function.blocks.iter().enumerate() {
            let expected_phi = block_idx == 0 && !predecessors[block_idx].is_empty()
                || predecessors[block_idx].len() > 1;
            for region in MemoryRegion::ALL {
                let phi = self.phi_for_block(block_idx, region);
                if expected_phi != phi.is_some() {
                    return Err(MemorySsaError::new(format!(
                        "block {block_idx} region {region:?} phi presence mismatch"
                    )));
                }
                if let Some(phi) = phi {
                    if self.entry_version(block_idx, region) != Some(phi.version) {
                        return Err(MemorySsaError::new("phi is not its block entry state"));
                    }
                    let mut expected = predecessors[block_idx]
                        .iter()
                        .map(|predecessor| {
                            self.exit_version(*predecessor, region)
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
                            version: MemoryVersionId::entry(region),
                        });
                    }
                    expected.sort();
                    if phi.incoming != expected {
                        return Err(MemorySsaError::new("memory phi inputs mismatch"));
                    }
                }

                let mut current = self
                    .entry_version(block_idx, region)
                    .ok_or_else(|| MemorySsaError::new("block entry state is missing"))?;
                for (instr_idx, _) in block.instrs.iter().enumerate() {
                    let address = InstrAddr {
                        block_idx,
                        instr_idx,
                    };
                    let Some(kind) = expected_accesses.get(&(address, region)).copied() else {
                        continue;
                    };
                    let access = self
                        .access_at(address, region)
                        .ok_or_else(|| MemorySsaError::new("memory effect is missing"))?;
                    if access.kind != kind || access.input != current {
                        return Err(MemorySsaError::new(format!(
                            "instruction {address:?} region {region:?} state mismatch"
                        )));
                    }
                    if let Some(output) = access.output {
                        current = output;
                    }
                }
                if self.exit_version(block_idx, region) != Some(current) {
                    return Err(MemorySsaError::new("block exit state mismatch"));
                }
            }
        }
        Ok(())
    }
}

/// Compute target-backed conservative MemorySSA for one LLIR function.
pub(crate) fn compute_memory_ssa(function: &LlirFunction, image: &ProgramImage) -> MemorySsaInfo {
    let predecessors = build_predecessors(function);
    let block_count = function.blocks.len();
    let effects = expected_accesses(function, image);
    let mut next_version = MemoryRegion::ALL.len();

    let mut phi_versions = BTreeMap::new();
    for block_idx in 0..block_count {
        if block_idx == 0 && !predecessors[block_idx].is_empty()
            || predecessors[block_idx].len() > 1
        {
            for region in MemoryRegion::ALL {
                phi_versions.insert((block_idx, region), MemoryVersionId(next_version));
                next_version = next_version.saturating_add(1);
            }
        }
    }

    let mut outputs = BTreeMap::new();
    let mut last_definition = BTreeMap::new();
    for ((address, region), kind) in &effects {
        if kind.writes() {
            let version = MemoryVersionId(next_version);
            next_version = next_version.saturating_add(1);
            outputs.insert((*address, *region), version);
            last_definition.insert((address.block_idx, *region), version);
        }
    }

    let mut entry_versions = BTreeMap::<BlockRegion, Option<MemoryVersionId>>::new();
    let mut exit_versions = BTreeMap::<BlockRegion, Option<MemoryVersionId>>::new();
    for block_idx in 0..block_count {
        for region in MemoryRegion::ALL {
            let key = (block_idx, region);
            let entry = phi_versions.get(&key).copied().or_else(|| {
                (block_idx == 0 || predecessors[block_idx].is_empty())
                    .then_some(MemoryVersionId::entry(region))
            });
            entry_versions.insert(key, entry);
            exit_versions.insert(key, last_definition.get(&key).copied());
        }
    }
    resolve_block_states(
        &predecessors,
        &last_definition,
        &mut entry_versions,
        &mut exit_versions,
    );
    for block_idx in 0..block_count {
        for region in MemoryRegion::ALL {
            let key = (block_idx, region);
            let entry = entry_versions
                .get(&key)
                .copied()
                .flatten()
                .unwrap_or_else(|| MemoryVersionId::entry(region));
            entry_versions.insert(key, Some(entry));
            let exit = exit_versions
                .get(&key)
                .copied()
                .flatten()
                .or_else(|| last_definition.get(&key).copied())
                .unwrap_or(entry);
            exit_versions.insert(key, Some(exit));
        }
    }

    let entry_versions = entry_versions
        .into_iter()
        .map(|(key, version)| (key, version.expect("all block entries were completed")))
        .collect::<BTreeMap<_, _>>();
    let exit_versions = exit_versions
        .into_iter()
        .map(|(key, version)| (key, version.expect("all block exits were completed")))
        .collect::<BTreeMap<_, _>>();

    let mut accesses = BTreeMap::new();
    for (block_idx, block) in function.blocks.iter().enumerate() {
        let mut current = MemoryRegion::ALL
            .into_iter()
            .map(|region| (region, entry_versions[&(block_idx, region)]))
            .collect::<BTreeMap<_, _>>();
        for (instr_idx, _) in block.instrs.iter().enumerate() {
            let address = InstrAddr {
                block_idx,
                instr_idx,
            };
            for region in MemoryRegion::ALL {
                let Some(kind) = effects.get(&(address, region)).copied() else {
                    continue;
                };
                let input = current[&region];
                let output = outputs.get(&(address, region)).copied();
                accesses.insert(
                    (address, region),
                    MemoryAccess {
                        kind,
                        region,
                        input,
                        output,
                    },
                );
                if let Some(output) = output {
                    current.insert(region, output);
                }
            }
        }
    }

    let mut phis = phi_versions
        .into_iter()
        .map(|((block_idx, region), version)| {
            let mut incoming = predecessors[block_idx]
                .iter()
                .map(|predecessor| MemoryIncoming {
                    predecessor: Some(*predecessor),
                    version: exit_versions[&(*predecessor, region)],
                })
                .collect::<Vec<_>>();
            if block_idx == 0 {
                incoming.push(MemoryIncoming {
                    predecessor: None,
                    version: MemoryVersionId::entry(region),
                });
            }
            incoming.sort();
            MemoryPhi {
                block_idx,
                region,
                version,
                incoming,
            }
        })
        .collect::<Vec<_>>();
    phis.sort_by_key(|phi| (phi.block_idx, phi.region));

    MemorySsaInfo {
        entry_versions,
        exit_versions,
        accesses,
        phis,
    }
}

fn resolve_block_states(
    predecessors: &[Vec<usize>],
    last_definition: &BTreeMap<BlockRegion, MemoryVersionId>,
    entry_versions: &mut BTreeMap<BlockRegion, Option<MemoryVersionId>>,
    exit_versions: &mut BTreeMap<BlockRegion, Option<MemoryVersionId>>,
) {
    for _ in 0..=predecessors.len() {
        let mut changed = false;
        for block_idx in 0..predecessors.len() {
            for region in MemoryRegion::ALL {
                let key = (block_idx, region);
                if entry_versions[&key].is_none() && predecessors[block_idx].len() == 1 {
                    let predecessor = (predecessors[block_idx][0], region);
                    if let Some(version) = exit_versions[&predecessor] {
                        entry_versions.insert(key, Some(version));
                        changed = true;
                    }
                }
                if exit_versions[&key].is_none() {
                    if let Some(version) =
                        last_definition.get(&key).copied().or(entry_versions[&key])
                    {
                        exit_versions.insert(key, Some(version));
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }
}

fn expected_accesses(
    function: &LlirFunction,
    image: &ProgramImage,
) -> BTreeMap<AccessKey, MemoryAccessKind> {
    let mut accesses = BTreeMap::new();
    for (block_idx, block) in function.blocks.iter().enumerate() {
        for (instr_idx, instruction) in block.instrs.iter().enumerate() {
            let address = InstrAddr {
                block_idx,
                instr_idx,
            };
            for (region, kind) in memory_effects(&instruction.op, image) {
                accesses.insert((address, region), kind);
            }
        }
    }
    accesses
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

fn memory_effects(op: &Op, image: &ProgramImage) -> Vec<(MemoryRegion, MemoryAccessKind)> {
    match op {
        Op::Load { addr, .. } | Op::CondLoad { addr, .. } => {
            addressed_effects(addr, MemoryAccessKind::Read, image)
        }
        Op::Store { addr, .. } | Op::CondStore { addr, .. } => {
            addressed_effects(addr, MemoryAccessKind::Write, image)
        }
        Op::Call { .. } | Op::Unknown { .. } => unknown_effects(true, true),
        Op::Intrinsic {
            reads_mem,
            writes_mem,
            ..
        } => unknown_effects(*reads_mem, *writes_mem),
        _ => Vec::new(),
    }
}

fn addressed_effects(
    address: &MemOp,
    kind: MemoryAccessKind,
    image: &ProgramImage,
) -> Vec<(MemoryRegion, MemoryAccessKind)> {
    let primary = primary_region_for_memop(address, image);
    if !matches!(
        primary,
        MemoryRegion::HeapUnknown | MemoryRegion::FullyUnknown
    ) {
        return vec![(primary, kind)];
    }

    match kind {
        MemoryAccessKind::Read => MemoryRegion::ALL
            .into_iter()
            .map(|region| (region, MemoryAccessKind::Read))
            .collect(),
        MemoryAccessKind::Write | MemoryAccessKind::Clobber => MemoryRegion::ALL
            .into_iter()
            .filter(|region| region.mutable())
            .map(|region| {
                let effect = if region == primary && primary == MemoryRegion::HeapUnknown {
                    kind
                } else {
                    MemoryAccessKind::Clobber
                };
                (region, effect)
            })
            .collect(),
    }
}

fn unknown_effects(reads: bool, writes: bool) -> Vec<(MemoryRegion, MemoryAccessKind)> {
    if !reads && !writes {
        return Vec::new();
    }
    MemoryRegion::ALL
        .into_iter()
        .filter_map(|region| {
            if writes && region.mutable() {
                Some((region, MemoryAccessKind::Clobber))
            } else if reads {
                Some((region, MemoryAccessKind::Read))
            } else {
                None
            }
        })
        .collect()
}

pub(crate) fn primary_region_for_memop(address: &MemOp, image: &ProgramImage) -> MemoryRegion {
    if address.segment.is_some() {
        return MemoryRegion::KnownGlobal;
    }
    if let Some(VReg::Phys(base)) = address.base.as_ref() {
        let base = crate::ir::abi::ssa_base(base);
        let roles = image.target().registers();
        if roles.is_stack_pointer(base) || roles.is_frame_pointer(base) {
            return MemoryRegion::Stack;
        }
    }
    if address.base.is_some() || address.index.is_some() {
        return MemoryRegion::HeapUnknown;
    }
    let Ok(absolute) = u64::try_from(address.disp) else {
        return MemoryRegion::FullyUnknown;
    };
    match image.memory_kind_at(absolute) {
        Some(ImageMemoryKind::ReadOnly) => MemoryRegion::ReadOnlyImage,
        Some(ImageMemoryKind::Writable) => MemoryRegion::KnownGlobal,
        None => MemoryRegion::FullyUnknown,
    }
}

#[cfg(test)]
#[path = "memory_ssa_tests.rs"]
mod tests;
