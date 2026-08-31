//! Splitting a reused lifter temporary into one temporary per SSA version.
//!
//! # Determinism contract
//!
//! The ids assigned here reach the rendered artifact, so the walk that
//! assigns them must not depend on hash iteration order. Both structures
//! below are ordered by construction -- `versions_by_base` is a vector
//! indexed by temporary id and each version list is sorted -- and the map
//! this returns is only ever probed by key, never iterated. Nothing in this
//! module may iterate a `HashMap`/`HashSet` whose order can reach an id.

use crate::ir::types::{LlirFunction, VReg};
use crate::ir::use_def::{def_ref, for_each_use, InstrAddr};

/// Remaps each reused lifter temporary `(Temp base, version)` to a fresh, unique
/// temporary id. A lifter reuses one `Temp` for many unrelated values within a
/// function; splitting them by SSA version makes each a single-def temporary, so
/// the single-use expression fold downstream can reassemble split address chains.
pub(crate) type TempRemap = std::collections::HashMap<(u32, u32), u32>;

/// Build the [`TempRemap`]: for every lifter temporary that is *reused* (has
/// more than one SSA version across the function), assign each `(base, version)`
/// a fresh, globally-unique temporary id. Temporaries with a single version are
/// left unchanged (identity), keeping their original ids to minimise churn.
///
/// This is a pure SSA renaming keyed off the same [`SsaInfo`] used for physical
/// registers: a use reading version `V` is remapped identically to the def that
/// produced `V`, so dataflow is preserved by construction.
pub(crate) fn build_temp_remap(lf: &LlirFunction, ssa: &crate::ir::ssa::SsaInfo) -> TempRemap {
    // Stable key iteration is part of the rendered-artifact contract: assigning
    // fresh ids by HashMap iteration made two identical decompilations spell the
    // same temporary as (for example) t35 and t36 in separate processes.
    //
    // Temporary ids are dense small integers, so the ordered map is an array
    // indexed by base and the ordered set of versions is a vector sorted and
    // deduplicated once at the end — the same ascending-base, ascending-version
    // walk the `BTreeMap<u32, BTreeSet<u32>>` gave, without a tree node per
    // version.
    let mut versions_by_base: Vec<Vec<u32>> = Vec::new();
    let mut note = |base: u32, version: u32, versions_by_base: &mut Vec<Vec<u32>>| {
        let index = base as usize;
        if index >= versions_by_base.len() {
            versions_by_base.resize(index + 1, Vec::new());
        }
        versions_by_base[index].push(version);
    };
    let mut max_temp_id = 0u32;
    for (bi, block) in lf.blocks.iter().enumerate() {
        for (ii, ins) in block.instrs.iter().enumerate() {
            let addr = InstrAddr {
                block_idx: bi,
                instr_idx: ii,
            };
            if let Some(VReg::Temp(base)) = def_ref(&ins.op) {
                max_temp_id = max_temp_id.max(*base);
                let v = ssa.def_version(lf, addr);
                note(*base, v, &mut versions_by_base);
            }
            let mut k = 0;
            for_each_use(&ins.op, |u| {
                let index = k;
                k += 1;
                if let VReg::Temp(base) = u {
                    max_temp_id = max_temp_id.max(*base);
                    let v = ssa.use_version(lf, addr, index);
                    note(*base, v, &mut versions_by_base);
                }
            });
        }
    }
    let mut remap = TempRemap::new();
    let mut next_id = max_temp_id + 1;
    for (base, versions) in versions_by_base.iter_mut().enumerate() {
        if versions.is_empty() {
            continue;
        }
        versions.sort_unstable();
        versions.dedup();
        let base = base as u32;
        if versions.len() <= 1 {
            for &v in versions.iter() {
                remap.insert((base, v), base);
            }
            continue;
        }
        // Reused: the lowest version keeps the original id, the rest get fresh
        // ids, so `Temp(base)` splits into distinct single-def temporaries.
        for (i, &v) in versions.iter().enumerate() {
            if i == 0 {
                remap.insert((base, v), base);
            } else {
                remap.insert((base, v), next_id);
                next_id += 1;
            }
        }
    }
    remap
}
