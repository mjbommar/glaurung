//! Static Single Assignment form over [`LlirFunction`].
//!
//! Rather than duplicate every LLIR op into an SSA variant, this module
//! produces a side-car [`SsaInfo`] that records:
//!
//! * the dominator tree of the function,
//! * dominance frontiers per block,
//! * phi-placement (where and for which VRegs),
//! * a version number for every def site, and
//! * a version number for every use site.
//!
//! Consumers keep the original `LlirFunction` and cross-reference it with
//! `SsaInfo` by [`InstrAddr`]. This keeps the LLIR types stable and avoids
//! a second parallel type hierarchy.
//!
//! Scope (v1):
//! * Operates on register VRegs (`VReg::Phys` and `VReg::Temp`) only —
//!   flag VRegs and memory are not versioned.
//! * Dominance is computed with the iterative algorithm of Cooper, Harvey &
//!   Kennedy (2001) — simple and well within our budgets for the function
//!   sizes we see today.
//! * Entry-block uses without a preceding def stay at version 0.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use crate::ir::types::{CallTarget, LlirFunction, MemOp, Op, VReg, Value};
use crate::ir::use_def::{def_uses, InstrAddr};

/// A phi node placed by SSA construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phi {
    pub block_idx: usize,
    /// The original VReg being renamed at this merge point.
    pub base: VReg,
    /// Version assigned to this phi's *result*.
    pub dst_version: u32,
    /// One (predecessor block, incoming version) entry per predecessor.
    pub incoming: Vec<(usize, u32)>,
}

/// SSA side-car information about an [`LlirFunction`].
#[derive(Debug, Default, Clone)]
pub struct SsaInfo {
    /// Immediate dominator of each block, by block index. The entry block
    /// has no idom and maps to `None`.
    pub idom: Vec<Option<usize>>,
    /// Dominance frontier sets, by block index.
    pub frontier: Vec<BTreeSet<usize>>,
    /// All placed phi nodes, grouped by their block.
    pub phis: Vec<Phi>,
    /// Version of the def written at this instruction (register-VReg defs only).
    pub def_versions: HashMap<InstrAddr, u32>,
    /// Version read at this `(instruction, use_index)` pair. The use_index
    /// corresponds to the source-order uses enumerated by [`def_uses`].
    pub use_versions: HashMap<(InstrAddr, usize), u32>,
}

/// Only register VRegs (`Phys` / `Temp`) are versioned. Flag VRegs are left
/// alone for now — a dedicated pass can version them once memory-effect
/// modelling lands.
fn is_ssa_reg(v: &VReg) -> bool {
    matches!(v, VReg::Phys(_) | VReg::Temp(_))
}

/// Walk operand values and memops for *register* uses in source order,
/// returning each as a VReg. Order must match [`def_uses`] so that
/// `use_index` aligns between the two modules.
fn uses_of_op_ordered(op: &Op) -> Vec<VReg> {
    let (_, uses) = def_uses(op);
    uses
}

fn write_reg(op: &Op) -> Option<VReg> {
    let (def, _) = def_uses(op);
    def.filter(is_ssa_reg)
}

/// Compute predecessor lists derived from each block's `succs`.
fn build_preds(lf: &LlirFunction) -> Vec<Vec<usize>> {
    let n = lf.blocks.len();
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
    // Map VA → block index for successor resolution.
    let va_to_idx: HashMap<u64, usize> = lf
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.start_va, i))
        .collect();
    for (i, b) in lf.blocks.iter().enumerate() {
        for s in &b.succs {
            if let Some(&j) = va_to_idx.get(s) {
                preds[j].push(i);
            }
        }
    }
    for p in &mut preds {
        p.sort_unstable();
        p.dedup();
    }
    preds
}

/// Iterative dominators via Cooper/Harvey/Kennedy, using a reverse-postorder
/// traversal of the CFG rooted at block 0.
///
/// Returns `(idom, rpo)` where `idom[i]` is the immediate dominator of block
/// `i` (None for the entry), and `rpo` is the reverse-post-order.
fn compute_dominators(lf: &LlirFunction, preds: &[Vec<usize>]) -> (Vec<Option<usize>>, Vec<usize>) {
    let n = lf.blocks.len();
    if n == 0 {
        return (Vec::new(), Vec::new());
    }

    // --- Reverse postorder via iterative DFS on successors -------------------
    let rpo: Vec<usize>;
    {
        let mut visited = vec![false; n];
        let mut order: Vec<usize> = Vec::with_capacity(n);
        let mut stack: Vec<(usize, usize)> = Vec::new(); // (node, next_succ_cursor)
        stack.push((0, 0));
        visited[0] = true;

        let succ_of = |bi: usize| -> Vec<usize> {
            let va_to_idx: HashMap<u64, usize> = lf
                .blocks
                .iter()
                .enumerate()
                .map(|(i, b)| (b.start_va, i))
                .collect();
            let mut out = Vec::new();
            for s in &lf.blocks[bi].succs {
                if let Some(&j) = va_to_idx.get(s) {
                    out.push(j);
                }
            }
            out
        };

        while let Some(&(node, cursor)) = stack.last() {
            let succs = succ_of(node);
            if cursor < succs.len() {
                let next = succs[cursor];
                // advance cursor
                let top = stack.last_mut().unwrap();
                top.1 += 1;
                if !visited[next] {
                    visited[next] = true;
                    stack.push((next, 0));
                }
            } else {
                order.push(node);
                stack.pop();
            }
        }
        // post-order is `order`; reverse-post-order is its reverse.
        order.reverse();
        // Any unreachable blocks get appended at the end (keeps them indexed
        // but they stay with no idom).
        for i in 0..n {
            if !visited[i] {
                order.push(i);
            }
        }
        rpo = order;
    }

    // `rpo_pos[block]` = index within rpo (smaller = earlier).
    let mut rpo_pos = vec![usize::MAX; n];
    for (i, &b) in rpo.iter().enumerate() {
        rpo_pos[b] = i;
    }

    // --- Dominator fixed-point ----------------------------------------------
    let mut idom: Vec<Option<usize>> = vec![None; n];
    idom[0] = Some(0); // self-dominate sentinel during the loop

    let intersect = |mut b1: usize, mut b2: usize, idom: &[Option<usize>]| -> usize {
        while b1 != b2 {
            while rpo_pos[b1] > rpo_pos[b2] {
                b1 = idom[b1].expect("idom must be set on finger in intersect");
            }
            while rpo_pos[b2] > rpo_pos[b1] {
                b2 = idom[b2].expect("idom must be set on finger in intersect");
            }
        }
        b1
    };

    let mut changed = true;
    while changed {
        changed = false;
        // Process blocks in reverse-postorder, skipping the entry.
        for &b in &rpo {
            if b == 0 {
                continue;
            }
            // Pick a processed predecessor as starting point.
            let mut new_idom: Option<usize> = None;
            for &p in &preds[b] {
                if idom[p].is_some() {
                    new_idom = Some(p);
                    break;
                }
            }
            let Some(mut new_idom) = new_idom else {
                continue; // unreachable
            };
            for &p in &preds[b] {
                if p == new_idom {
                    continue;
                }
                if idom[p].is_some() {
                    new_idom = intersect(p, new_idom, &idom);
                }
            }
            if idom[b] != Some(new_idom) {
                idom[b] = Some(new_idom);
                changed = true;
            }
        }
    }

    // Entry dominates itself; surface as None per our convention.
    idom[0] = None;
    (idom, rpo)
}

/// Compute dominance frontier for each block, given immediate dominators and
/// predecessor lists.
fn compute_frontiers(idom: &[Option<usize>], preds: &[Vec<usize>]) -> Vec<BTreeSet<usize>> {
    let n = idom.len();
    let mut df: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); n];
    for b in 0..n {
        if preds[b].len() < 2 {
            continue;
        }
        let Some(b_idom) = idom[b] else { continue };
        for &p in &preds[b] {
            let mut runner = p;
            while runner != b_idom {
                df[runner].insert(b);
                let Some(next) = idom[runner] else { break };
                if next == runner {
                    break;
                }
                runner = next;
            }
        }
    }
    df
}

/// Compute which blocks define each SSA-eligible VReg.
fn def_blocks(lf: &LlirFunction) -> BTreeMap<VReg, BTreeSet<usize>> {
    let mut out: BTreeMap<VReg, BTreeSet<usize>> = BTreeMap::new();
    for (bi, b) in lf.blocks.iter().enumerate() {
        for ins in &b.instrs {
            if let Some(d) = write_reg(&ins.op) {
                out.entry(d).or_default().insert(bi);
            }
        }
    }
    out
}

/// Place phi nodes at the iterated dominance frontier of the def-blocks of
/// each variable. Returns a parallel vector indexed by block number of phi
/// records (one per VReg requiring a phi at that block).
fn place_phis(
    def_blocks: &BTreeMap<VReg, BTreeSet<usize>>,
    frontier: &[BTreeSet<usize>],
    preds: &[Vec<usize>],
) -> Vec<Vec<(VReg, Vec<usize>)>> {
    let n = frontier.len();
    let mut phi_blocks: Vec<Vec<(VReg, Vec<usize>)>> = vec![Vec::new(); n];
    for (v, defs) in def_blocks {
        let mut work: VecDeque<usize> = defs.iter().copied().collect();
        let mut has_phi: HashSet<usize> = HashSet::new();
        let mut in_work: HashSet<usize> = defs.iter().copied().collect();
        while let Some(b) = work.pop_front() {
            in_work.remove(&b);
            for &y in &frontier[b] {
                if has_phi.insert(y) {
                    phi_blocks[y].push((v.clone(), preds[y].clone()));
                    if !defs.contains(&y) && !in_work.contains(&y) {
                        work.push_back(y);
                        in_work.insert(y);
                    }
                }
            }
        }
    }
    phi_blocks
}

/// Build child lists from the idom array (for dom-tree DFS).
fn dom_children(idom: &[Option<usize>]) -> Vec<Vec<usize>> {
    let n = idom.len();
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (b, i) in idom.iter().enumerate() {
        if let Some(p) = i {
            if *p != b {
                children[*p].push(b);
            }
        }
    }
    children
}

/// Classic Cytron-style renaming.
fn rename(
    lf: &LlirFunction,
    idom: &[Option<usize>],
    phi_blocks: &[Vec<(VReg, Vec<usize>)>],
) -> (SsaInfo, Vec<Vec<Phi>>) {
    let n = lf.blocks.len();
    let children = dom_children(idom);

    // Counter and version stack per VReg.
    let mut counter: HashMap<VReg, u32> = HashMap::new();
    let mut stack: HashMap<VReg, Vec<u32>> = HashMap::new();

    let mut def_versions: HashMap<InstrAddr, u32> = HashMap::new();
    let mut use_versions: HashMap<(InstrAddr, usize), u32> = HashMap::new();
    // Phi results and incoming version slots, filled in as we rename.
    let mut phi_dst: Vec<HashMap<VReg, u32>> = vec![HashMap::new(); n];
    let mut phi_inputs: Vec<HashMap<VReg, HashMap<usize, u32>>> = vec![HashMap::new(); n];

    fn new_version(counter: &mut HashMap<VReg, u32>, stack: &mut HashMap<VReg, Vec<u32>>, v: &VReg) -> u32 {
        let c = counter.entry(v.clone()).or_insert(0);
        let ver = *c;
        *c += 1;
        stack.entry(v.clone()).or_default().push(ver);
        ver
    }

    fn top_version(stack: &HashMap<VReg, Vec<u32>>, v: &VReg) -> u32 {
        stack.get(v).and_then(|s| s.last().copied()).unwrap_or(0)
    }

    // Iterative DFS of the dominator tree so we don't blow the stack on deep
    // CFGs. Each stack entry is (block, child_cursor, pushed_vregs).
    let mut dfs: Vec<(usize, usize, Vec<VReg>)> = Vec::new();
    dfs.push((0, 0, Vec::new()));

    while let Some(&mut (block, cursor, _)) = dfs.last_mut() {
        if cursor == 0 {
            // --- Entering `block`: rename all defs and uses here ------------
            let mut pushed_here: Vec<VReg> = Vec::new();

            // 1. Phis defined at this block get fresh versions.
            for (v, _preds) in &phi_blocks[block] {
                let ver = new_version(&mut counter, &mut stack, v);
                phi_dst[block].insert(v.clone(), ver);
                pushed_here.push(v.clone());
            }

            // 2. Rename each LLIR op's uses, then its def.
            for (ii, ins) in lf.blocks[block].instrs.iter().enumerate() {
                let addr = InstrAddr {
                    block_idx: block,
                    instr_idx: ii,
                };
                let uses = uses_of_op_ordered(&ins.op);
                for (ui, u) in uses.iter().enumerate() {
                    if is_ssa_reg(u) {
                        use_versions.insert((addr, ui), top_version(&stack, u));
                    }
                }
                if let Some(d) = write_reg(&ins.op) {
                    let ver = new_version(&mut counter, &mut stack, &d);
                    def_versions.insert(addr, ver);
                    pushed_here.push(d);
                }
            }

            // 3. Fill successor phi's incoming-version slots for this predecessor.
            let succ_blocks: Vec<usize> = {
                let va_to_idx: HashMap<u64, usize> = lf
                    .blocks
                    .iter()
                    .enumerate()
                    .map(|(i, b)| (b.start_va, i))
                    .collect();
                lf.blocks[block]
                    .succs
                    .iter()
                    .filter_map(|s| va_to_idx.get(s).copied())
                    .collect()
            };
            for succ in &succ_blocks {
                for (v, _preds) in &phi_blocks[*succ] {
                    let ver = top_version(&stack, v);
                    phi_inputs[*succ]
                        .entry(v.clone())
                        .or_default()
                        .insert(block, ver);
                }
            }

            dfs.last_mut().unwrap().2 = pushed_here;
        }

        // --- Descend into next child, if any -----------------------------------
        let (block, cursor) = {
            let top = dfs.last().unwrap();
            (top.0, top.1)
        };
        let children_of_block = &children[block];
        if cursor < children_of_block.len() {
            let next = children_of_block[cursor];
            dfs.last_mut().unwrap().1 = cursor + 1;
            dfs.push((next, 0, Vec::new()));
            continue;
        }

        // --- Leaving `block`: pop versions we pushed --------------------------
        let (_, _, pushed_here) = dfs.pop().unwrap();
        for v in pushed_here {
            if let Some(s) = stack.get_mut(&v) {
                s.pop();
            }
        }
    }

    // Materialise `Phi` records from the per-block maps.
    let mut phis: Vec<Phi> = Vec::new();
    let mut per_block_phis: Vec<Vec<Phi>> = vec![Vec::new(); n];
    for bi in 0..n {
        for (v, _preds) in &phi_blocks[bi] {
            let dst_version = *phi_dst[bi]
                .get(v)
                .expect("phi dst not assigned during renaming");
            let incoming_map = phi_inputs[bi].get(v).cloned().unwrap_or_default();
            let mut incoming: Vec<(usize, u32)> = incoming_map.into_iter().collect();
            incoming.sort_by_key(|(p, _)| *p);
            let phi = Phi {
                block_idx: bi,
                base: v.clone(),
                dst_version,
                incoming,
            };
            per_block_phis[bi].push(phi.clone());
            phis.push(phi);
        }
    }

    let info = SsaInfo {
        idom: idom.to_vec(),
        frontier: Vec::new(), // filled in by caller
        phis,
        def_versions,
        use_versions,
    };
    (info, per_block_phis)
}

/// Compute SSA information for `lf`.
pub fn compute_ssa(lf: &LlirFunction) -> SsaInfo {
    let preds = build_preds(lf);
    let (idom, _rpo) = compute_dominators(lf, &preds);
    let frontier = compute_frontiers(&idom, &preds);
    let def_blocks = def_blocks(lf);
    let phi_blocks = place_phis(&def_blocks, &frontier, &preds);
    let (mut info, _per_block) = rename(lf, &idom, &phi_blocks);
    info.frontier = frontier;
    info
}

// -- suppress unused-import lints when no consumer uses MemOp/Value pattern --
#[allow(dead_code)]
fn _keep_imports(_m: &MemOp, _v: &Value, _c: &CallTarget) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::{BinOp, LlirBlock, LlirInstr, Op, VReg};

    /// Build an LLIR function with given (va_start, ops, succs_vas) per block.
    fn mk_cfg(spec: Vec<(u64, Vec<Op>, Vec<u64>)>) -> LlirFunction {
        let entry_va = spec.first().map(|(s, _, _)| *s).unwrap_or(0);
        let blocks = spec
            .into_iter()
            .map(|(start_va, ops, succs)| LlirBlock {
                start_va,
                end_va: start_va + 0x100,
                instrs: ops
                    .into_iter()
                    .enumerate()
                    .map(|(j, op)| LlirInstr {
                        va: start_va + (j as u64) * 4,
                        op,
                    })
                    .collect(),
                succs,
            })
            .collect();
        LlirFunction { entry_va, blocks }
    }

    fn assign(reg: &str, c: i64) -> Op {
        Op::Assign {
            dst: VReg::phys(reg),
            src: Value::Const(c),
        }
    }

    fn add(reg: &str, a: &str, b: &str) -> Op {
        Op::Bin {
            dst: VReg::phys(reg),
            op: BinOp::Add,
            lhs: Value::Reg(VReg::phys(a)),
            rhs: Value::Reg(VReg::phys(b)),
        }
    }

    #[test]
    fn single_block_no_phis_versions_increase_per_def() {
        // B0: %rax = 1 ; %rax = 2 ; %rbx = rax
        let lf = mk_cfg(vec![(
            0x1000,
            vec![
                assign("rax", 1),
                assign("rax", 2),
                Op::Assign {
                    dst: VReg::phys("rbx"),
                    src: Value::Reg(VReg::phys("rax")),
                },
            ],
            vec![],
        )]);
        let info = compute_ssa(&lf);
        assert!(info.phis.is_empty(), "single block has no phis");
        let defs_a = info.def_versions[&InstrAddr {
            block_idx: 0,
            instr_idx: 0,
        }];
        let defs_b = info.def_versions[&InstrAddr {
            block_idx: 0,
            instr_idx: 1,
        }];
        assert_ne!(defs_a, defs_b, "two defs of rax must have distinct versions");
        // rbx read uses rax at its second version.
        let read_ver = info.use_versions[&(
            InstrAddr {
                block_idx: 0,
                instr_idx: 2,
            },
            0,
        )];
        assert_eq!(read_ver, defs_b);
    }

    #[test]
    fn diamond_cfg_inserts_phi_at_merge() {
        //        B0: cond
        //       /     \
        //      B1      B2        (each defines %rax)
        //       \     /
        //        B3: use rax     ← must phi
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100, 0x1200]),
            (0x1100, vec![assign("rax", 1)], vec![0x1300]),
            (0x1200, vec![assign("rax", 2)], vec![0x1300]),
            (
                0x1300,
                vec![Op::Assign {
                    dst: VReg::phys("rbx"),
                    src: Value::Reg(VReg::phys("rax")),
                }],
                vec![],
            ),
        ]);
        let info = compute_ssa(&lf);
        // Exactly one phi, at block 3, for rax.
        assert_eq!(info.phis.len(), 1, "expected one phi: {:#?}", info.phis);
        let p = &info.phis[0];
        assert_eq!(p.block_idx, 3);
        assert_eq!(p.base, VReg::phys("rax"));
        assert_eq!(p.incoming.len(), 2);
        // The two incoming versions must differ and come from the two
        // predecessor blocks 1 and 2.
        let pred_blocks: Vec<usize> = p.incoming.iter().map(|(b, _)| *b).collect();
        assert_eq!(pred_blocks, vec![1, 2]);
        let versions: Vec<u32> = p.incoming.iter().map(|(_, v)| *v).collect();
        assert_ne!(versions[0], versions[1]);
    }

    #[test]
    fn loop_with_counter_gets_phi_at_header() {
        //    B0: %i = 0
        //       |
        //       v
        //    B1 (header): use i, cmp i, 10
        //      /       \
        //    B2: i = i+1      B3 (exit)
        //      \______________/
        // Back-edge from B2 → B1 forces a phi for i at B1.
        let lf = mk_cfg(vec![
            (0x1000, vec![assign("i", 0)], vec![0x1100]),
            (
                0x1100,
                vec![Op::Assign {
                    dst: VReg::phys("tmp"),
                    src: Value::Reg(VReg::phys("i")),
                }],
                vec![0x1200, 0x1300],
            ),
            (0x1200, vec![add("i", "i", "one")], vec![0x1100]),
            (0x1300, vec![Op::Return], vec![]),
        ]);
        let info = compute_ssa(&lf);
        // Find the phi for %i.
        let phi_for_i: Vec<&Phi> = info
            .phis
            .iter()
            .filter(|p| p.base == VReg::phys("i"))
            .collect();
        assert_eq!(phi_for_i.len(), 1, "expected phi for i: {:#?}", info.phis);
        assert_eq!(phi_for_i[0].block_idx, 1, "phi must sit at loop header");
    }

    #[test]
    fn works_on_real_lifted_function() {
        use crate::analysis::cfg::{analyze_functions_bytes, Budgets};
        use crate::core::binary::Arch;
        use crate::ir::lift_function::lift_function_from_bytes;
        let path = std::path::Path::new(
            "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2",
        );
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let (funcs, _cg) = analyze_functions_bytes(
            &data,
            &Budgets {
                max_functions: 4,
                max_blocks: 128,
                max_instructions: 2000,
                timeout_ms: 500,
            },
        );
        for f in &funcs {
            if let Some(lf) = lift_function_from_bytes(&data, f, Arch::X86_64) {
                let info = compute_ssa(&lf);
                // No assertions about exact counts — just that SSA completes
                // on real input without panics and produces internally-
                // consistent version numbers.
                for (_addr, ver) in &info.def_versions {
                    assert!(*ver < u32::MAX);
                }
                for ((_addr, _ui), ver) in &info.use_versions {
                    assert!(*ver < u32::MAX);
                }
                // Every phi's incoming list must only reference this
                // function's predecessor blocks.
                let preds = build_preds(&lf);
                for p in &info.phis {
                    for (pred_b, _) in &p.incoming {
                        assert!(
                            preds[p.block_idx].contains(pred_b),
                            "phi at block {} lists non-predecessor {}",
                            p.block_idx,
                            pred_b,
                        );
                    }
                }
            }
        }
    }
}
