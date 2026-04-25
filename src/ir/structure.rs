//! Structural analysis — recover high-level control-flow structures from an
//! [`LlirFunction`]'s CFG.
//!
//! The output is a [`Region`] tree: a compact description of the function's
//! control flow in terms of sequences, conditionals, and natural loops. This
//! is the substrate a future decompiler AST pass will consume.
//!
//! Scope (v1):
//!
//! * Straight-line sequences (`Seq`).
//! * Single-entry diamond `if-then` and `if-then-else` with a common join.
//! * Natural loops with a single back-edge and a single header (`While`).
//! * Anything else is preserved as [`Region::Unstructured`] carrying the raw
//!   block indices so no control flow is ever silently dropped.
//!
//! The algorithm walks the CFG from the entry block, pattern-matching on
//! successor counts and dominator info. It is intentionally simple and
//! conservative; irreducible or heavily goto-laden code degrades gracefully
//! to `Unstructured`.

use std::collections::{HashMap, HashSet};

use crate::ir::ssa::SsaInfo;
use crate::ir::types::LlirFunction;

/// One structured region in the recovered tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Region {
    /// A single basic block, referenced by its index in `LlirFunction::blocks`.
    Block(usize),
    /// Straight-line sequence — the regions execute in order.
    Seq(Vec<Region>),
    /// `if (cond) then { then_r }` — no else arm. `join` is the merge block
    /// that control rejoins after the conditional, or `None` if the `then`
    /// arm exits the function without returning to a join.
    IfThen {
        cond: usize,
        then_r: Box<Region>,
        join: Option<usize>,
    },
    /// `if (cond) then { then_r } else { else_r }` joining at `join`.
    IfThenElse {
        cond: usize,
        then_r: Box<Region>,
        else_r: Box<Region>,
        join: Option<usize>,
    },
    /// `while (...) { body }` — header branches to body or exit; body's
    /// back-edge returns to header.
    While {
        header: usize,
        body: Box<Region>,
        exit: Option<usize>,
    },
    /// Fallback — a set of blocks that didn't fit any recognised pattern.
    Unstructured(Vec<usize>),
}

impl Region {
    /// Yield every block index referenced by this region (DFS order). Used to
    /// verify that structural analysis doesn't silently lose blocks.
    pub fn blocks(&self) -> Vec<usize> {
        fn walk(r: &Region, out: &mut Vec<usize>) {
            match r {
                Region::Block(b) => out.push(*b),
                Region::Seq(parts) => {
                    for p in parts {
                        walk(p, out);
                    }
                }
                Region::IfThen { cond, then_r, join } => {
                    out.push(*cond);
                    walk(then_r, out);
                    if let Some(j) = join {
                        out.push(*j);
                    }
                }
                Region::IfThenElse {
                    cond,
                    then_r,
                    else_r,
                    join,
                } => {
                    out.push(*cond);
                    walk(then_r, out);
                    walk(else_r, out);
                    if let Some(j) = join {
                        out.push(*j);
                    }
                }
                Region::While { header, body, exit } => {
                    out.push(*header);
                    walk(body, out);
                    if let Some(e) = exit {
                        out.push(*e);
                    }
                }
                Region::Unstructured(bs) => out.extend(bs.iter().copied()),
            }
        }
        let mut v = Vec::new();
        walk(self, &mut v);
        v
    }
}

/// Lookup helpers built once per call to [`recover`].
struct Cfg {
    /// Block index → list of successor block indices.
    succs: Vec<Vec<usize>>,
    /// Block index → list of predecessor block indices.
    preds: Vec<Vec<usize>>,
    /// Cached: true iff block `a` dominates block `b`.
    /// We precompute a dense bitset because functions are small.
    dom: Vec<Vec<bool>>,
}

impl Cfg {
    fn from(lf: &LlirFunction, ssa: &SsaInfo) -> Self {
        let n = lf.blocks.len();
        let va_to_idx: HashMap<u64, usize> = lf
            .blocks
            .iter()
            .enumerate()
            .map(|(i, b)| (b.start_va, i))
            .collect();
        let mut succs: Vec<Vec<usize>> = vec![Vec::new(); n];
        let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (i, b) in lf.blocks.iter().enumerate() {
            for s_va in &b.succs {
                if let Some(&j) = va_to_idx.get(s_va) {
                    succs[i].push(j);
                    preds[j].push(i);
                }
            }
        }
        for v in succs.iter_mut().chain(preds.iter_mut()) {
            v.sort_unstable();
            v.dedup();
        }

        // Materialise the dominance relation from idom chains.
        let mut dom: Vec<Vec<bool>> = vec![vec![false; n]; n];
        for i in 0..n {
            // Every reachable block is dominated by itself (entry included).
            // Unreachable blocks (idom == None && i != 0) are handled by
            // leaving their row all-false, which causes structural analysis
            // to treat them as isolated and bucket them into Unstructured.
            if i == 0 || ssa.idom.get(i).and_then(|x| *x).is_some() {
                let mut cur = Some(i);
                while let Some(c) = cur {
                    dom[c][i] = true;
                    if c == 0 {
                        break;
                    }
                    cur = ssa.idom.get(c).and_then(|x| *x);
                }
            }
        }
        Cfg { succs, preds, dom }
    }

    fn dominates(&self, a: usize, b: usize) -> bool {
        self.dom[a][b]
    }
}

/// Single public entry point — build a region tree for the function.
pub fn recover(lf: &LlirFunction, ssa: &SsaInfo) -> Region {
    if lf.blocks.is_empty() {
        return Region::Unstructured(Vec::new());
    }
    let cfg = Cfg::from(lf, ssa);
    let mut visited: HashSet<usize> = HashSet::new();
    let region = build(0, &cfg, &mut visited, None);

    // Any blocks we never visited (unreachable or in an irreducible knot)
    // get tacked on as an Unstructured sibling so nothing is lost.
    let leftover: Vec<usize> = (0..lf.blocks.len()).filter(|b| !visited.contains(b)).collect();
    if leftover.is_empty() {
        region
    } else {
        let mut parts = flatten_seq(region);
        parts.push(Region::Unstructured(leftover));
        Region::Seq(parts)
    }
}

fn flatten_seq(r: Region) -> Vec<Region> {
    match r {
        Region::Seq(parts) => parts,
        other => vec![other],
    }
}

/// Recursively build a Region starting at `start`, stopping at `stop_at`
/// (exclusive). `visited` tracks blocks consumed into the output.
fn build(
    start: usize,
    cfg: &Cfg,
    visited: &mut HashSet<usize>,
    stop_at: Option<usize>,
) -> Region {
    let mut parts: Vec<Region> = Vec::new();
    let mut cur = start;

    loop {
        if Some(cur) == stop_at {
            break;
        }
        if !visited.insert(cur) {
            // Already consumed — avoid infinite loops on back-edges or shared
            // successors we don't currently model structurally.
            break;
        }

        // --- Natural loop detection: any successor that dominates `cur`  ----
        // means there's a back edge from `cur` to that dominator, forming a
        // natural loop with that block as header. We only structure this when
        // `cur` itself is the loop header (single-block loop) or when we are
        // already sitting at the header.
        if let Some(loop_r) = detect_natural_loop(cur, cfg, visited) {
            parts.push(loop_r.region);
            match loop_r.exit {
                Some(next) => {
                    cur = next;
                    continue;
                }
                None => break,
            }
        }

        // --- Conditional shapes ---------------------------------------------
        if cfg.succs[cur].len() == 2 {
            if let Some((ite, after)) = detect_if_shape(cur, cfg, visited) {
                parts.push(ite);
                match after {
                    Some(next) => {
                        cur = next;
                        continue;
                    }
                    None => break,
                }
            }
        }

        // --- Default: straight-line block -----------------------------------
        parts.push(Region::Block(cur));

        // Advance through a single-successor chain. We used to require the
        // successor have exactly one predecessor, but that broke loop-header
        // recognition: a header has multiple preds (entry + back-edge), yet
        // we still want the outer DFS to reach it so the natural-loop
        // detector can fire. We rely on `visited` to prevent re-entry and on
        // `stop_at` to bound recursion inside sub-regions.
        let succs = &cfg.succs[cur];
        if succs.len() != 1 {
            break;
        }
        let next = succs[0];
        if Some(next) == stop_at {
            break;
        }
        if visited.contains(&next) {
            break;
        }
        cur = next;
    }

    if parts.len() == 1 {
        parts.pop().unwrap()
    } else {
        Region::Seq(parts)
    }
}

struct LoopRegion {
    region: Region,
    exit: Option<usize>,
}

/// Recognise a natural while-loop headed at `header`.
///
/// The pattern:
///   * `header` has exactly two successors: `body_head` and `exit_block`.
///   * `body_head` eventually reaches back to `header` via a block `back` whose
///     only successor is `header` (single back-edge).
///   * `header` dominates `body_head` and `back`.
fn detect_natural_loop(
    header: usize,
    cfg: &Cfg,
    visited: &mut HashSet<usize>,
) -> Option<LoopRegion> {
    if cfg.succs[header].len() != 2 {
        return None;
    }
    let a = cfg.succs[header][0];
    let b = cfg.succs[header][1];

    // Find whichever successor's sub-path contains a back-edge to `header`.
    for &(body_head, exit) in &[(a, b), (b, a)] {
        if !cfg.dominates(header, body_head) {
            continue;
        }
        // Walk a linear chain from body_head and see whether it loops back.
        if let Some(body_region) = collect_loop_body(body_head, header, cfg, visited) {
            visited.insert(header);
            return Some(LoopRegion {
                region: Region::While {
                    header,
                    body: Box::new(body_region),
                    exit: Some(exit),
                },
                exit: Some(exit),
            });
        }
    }
    None
}

/// Collect a loop body starting at `body_head` whose back-edge returns to
/// `header`. Returns None if the shape isn't recognisable.
fn collect_loop_body(
    body_head: usize,
    header: usize,
    cfg: &Cfg,
    visited: &mut HashSet<usize>,
) -> Option<Region> {
    // The simplest case we handle: body is a single block whose only
    // successor is `header`.
    if cfg.succs[body_head] == vec![header] {
        visited.insert(body_head);
        return Some(Region::Block(body_head));
    }
    // A slightly richer case: body is a straight-line chain ending with a
    // block whose only successor is `header`.
    let mut parts: Vec<Region> = Vec::new();
    let mut cur = body_head;
    let mut local_visited: HashSet<usize> = HashSet::new();
    loop {
        if !local_visited.insert(cur) {
            return None; // internal cycle — too complex for v1
        }
        parts.push(Region::Block(cur));
        let succs = &cfg.succs[cur];
        if succs.len() == 1 && succs[0] == header {
            // Commit
            for b in &local_visited {
                visited.insert(*b);
            }
            return Some(if parts.len() == 1 {
                parts.pop().unwrap()
            } else {
                Region::Seq(parts)
            });
        }
        if succs.len() != 1 {
            return None;
        }
        let next = succs[0];
        if cfg.preds[next].len() != 1 {
            return None;
        }
        cur = next;
    }
}

/// Recognise an if-then / if-then-else diamond rooted at `cond`.
///
/// Returns `Some((region, after))` when we can structurally absorb the whole
/// conditional and continue at `after` (the join block, or None if one of
/// the arms exits outright).
fn detect_if_shape(
    cond: usize,
    cfg: &Cfg,
    visited: &mut HashSet<usize>,
) -> Option<(Region, Option<usize>)> {
    let t = cfg.succs[cond][0];
    let e = cfg.succs[cond][1];

    // --- if-then-else ------------------------------------------------------
    // Both arms have `cond` as their only predecessor and share a common
    // successor `join` that has exactly {arm_then_last, arm_else_last} as
    // predecessors.
    let then_single = cfg.preds[t] == vec![cond] && cfg.succs[t].len() == 1;
    let else_single = cfg.preds[e] == vec![cond] && cfg.succs[e].len() == 1;
    if then_single && else_single && cfg.succs[t][0] == cfg.succs[e][0] {
        let join = cfg.succs[t][0];
        // Mark cond consumed, recurse on arms.
        visited.insert(cond);
        let then_r = build(t, cfg, visited, Some(join));
        let else_r = build(e, cfg, visited, Some(join));
        return Some((
            Region::IfThenElse {
                cond,
                then_r: Box::new(then_r),
                else_r: Box::new(else_r),
                join: Some(join),
            },
            Some(join),
        ));
    }

    // --- if-then (no else) -------------------------------------------------
    // `t` is the "body" arm: cond → t → join; and `e` is the join directly.
    for &(body, join) in &[(t, e), (e, t)] {
        let body_single = cfg.preds[body] == vec![cond] && cfg.succs[body] == vec![join];
        if body_single && cfg.preds[join].contains(&cond) {
            visited.insert(cond);
            let then_r = build(body, cfg, visited, Some(join));
            return Some((
                Region::IfThen {
                    cond,
                    then_r: Box::new(then_r),
                    join: Some(join),
                },
                Some(join),
            ));
        }
    }

    // --- if-then with early-exit body (#192) -------------------------------
    // The shape: one arm terminates the function (return / unreachable), the
    // other continues. The terminating arm becomes the `then` body of an
    // IfThen with `join: None`, and the surviving arm is the continuation.
    //
    // This catches the canonical `if (cond) return;` pattern that the
    // earlier structurer left as Unstructured. The terminating arm must be
    // single-pred-from-cond so we don't speculatively pull in shared
    // exit blocks reached by multiple gotos.
    for &(body, cont) in &[(t, e), (e, t)] {
        let body_terminates = cfg.preds[body] == vec![cond] && cfg.succs[body].is_empty();
        if body_terminates {
            visited.insert(cond);
            let then_r = build(body, cfg, visited, None);
            return Some((
                Region::IfThen {
                    cond,
                    then_r: Box::new(then_r),
                    join: None,
                },
                Some(cont),
            ));
        }
    }

    // --- if-then with shared-exit goto (#192) ------------------------------
    // The richer shape: one arm is a terminating block that is reached from
    // multiple sites (e.g. `L_end: return;` shared by every `if (cond) goto
    // L_end;` in the function). We clone-inline the terminating block into
    // this if-then's body but DO NOT mark it visited, so other branches in
    // the same function can also fold their gotos away — and so the outer
    // build will still emit the block as the function's tail.
    //
    // The block-index reference inside `IfThen { then_r: Region::Block(b) }`
    // causes the AST lowerer to render the terminating statements twice
    // (once per if-goto site, once at the tail), which is the right
    // semantics: each if statement is conceptually `if (cond) { return; }`.
    for &(body, cont) in &[(t, e), (e, t)] {
        let body_is_shared_exit =
            cfg.succs[body].is_empty() && cfg.preds[body].len() > 1;
        if body_is_shared_exit {
            visited.insert(cond);
            // Don't mark `body` as visited — let outer recursion emit it
            // when we eventually fall through (or when another branch also
            // references it).
            return Some((
                Region::IfThen {
                    cond,
                    then_r: Box::new(Region::Block(body)),
                    join: None,
                },
                Some(cont),
            ));
        }
    }

    // --- if-then-else where both arms terminate (#192) ---------------------
    // Both arms exit the function; there is no continuation. We emit an
    // IfThenElse with join=None and signal the outer build to stop.
    let t_terminates = cfg.preds[t] == vec![cond] && cfg.succs[t].is_empty();
    let e_terminates = cfg.preds[e] == vec![cond] && cfg.succs[e].is_empty();
    if t_terminates && e_terminates {
        visited.insert(cond);
        let then_r = build(t, cfg, visited, None);
        let else_r = build(e, cfg, visited, None);
        return Some((
            Region::IfThenElse {
                cond,
                then_r: Box::new(then_r),
                else_r: Box::new(else_r),
                join: None,
            },
            None,
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ssa::compute_ssa;
    use crate::ir::types::{LlirBlock, LlirInstr, Op};

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

    fn recover_for(lf: &LlirFunction) -> Region {
        let ssa = compute_ssa(lf);
        recover(lf, &ssa)
    }

    #[test]
    fn straight_line_collapses_to_seq() {
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100]),
            (0x1100, vec![Op::Nop], vec![0x1200]),
            (0x1200, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        match r {
            Region::Seq(parts) => {
                assert_eq!(parts.len(), 3);
                for (i, p) in parts.iter().enumerate() {
                    assert_eq!(p, &Region::Block(i));
                }
            }
            other => panic!("expected Seq; got {:?}", other),
        }
    }

    #[test]
    fn diamond_recovers_as_if_then_else() {
        //     B0 cond
        //    /       \
        //   B1        B2
        //    \       /
        //     B3 join
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100, 0x1200]),
            (0x1100, vec![Op::Nop], vec![0x1300]),
            (0x1200, vec![Op::Nop], vec![0x1300]),
            (0x1300, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        // Expect Seq([IfThenElse{cond=0, then=Block(1), else=Block(2), join=3}, Block(3)]).
        match r {
            Region::Seq(parts) => {
                assert_eq!(parts.len(), 2);
                match &parts[0] {
                    Region::IfThenElse {
                        cond,
                        then_r,
                        else_r,
                        join,
                    } => {
                        assert_eq!(*cond, 0);
                        assert_eq!(**then_r, Region::Block(1));
                        assert_eq!(**else_r, Region::Block(2));
                        assert_eq!(*join, Some(3));
                    }
                    other => panic!("expected IfThenElse; got {:?}", other),
                }
                assert_eq!(parts[1], Region::Block(3));
            }
            other => panic!("expected Seq; got {:?}", other),
        }
    }

    #[test]
    fn if_then_without_else_recognised() {
        //   B0 cond
        //   / \
        //  B1 |
        //   \ |
        //    B2 join
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100, 0x1200]),
            (0x1100, vec![Op::Nop], vec![0x1200]),
            (0x1200, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        match r {
            Region::Seq(parts) => {
                assert_eq!(parts.len(), 2);
                match &parts[0] {
                    Region::IfThen { cond, then_r, join } => {
                        assert_eq!(*cond, 0);
                        assert_eq!(**then_r, Region::Block(1));
                        assert_eq!(*join, Some(2));
                    }
                    other => panic!("expected IfThen; got {:?}", other),
                }
                assert_eq!(parts[1], Region::Block(2));
            }
            other => panic!("expected Seq; got {:?}", other),
        }
    }

    #[test]
    fn while_loop_recovered_with_body_and_exit() {
        //   B0: entry (straight into header)
        //   B1: header, two succs (body=B2, exit=B3)
        //   B2: body → B1
        //   B3: return
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100]),
            (0x1100, vec![Op::Nop], vec![0x1200, 0x1300]),
            (0x1200, vec![Op::Nop], vec![0x1100]),
            (0x1300, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        match r {
            Region::Seq(parts) => {
                assert!(parts.len() >= 2, "expected entry block + loop + exit");
                // First part must be Block(0) (the entry).
                assert_eq!(parts[0], Region::Block(0));
                // Second part must be While with header=1 and body=Block(2).
                match &parts[1] {
                    Region::While { header, body, exit } => {
                        assert_eq!(*header, 1);
                        assert_eq!(**body, Region::Block(2));
                        assert_eq!(*exit, Some(3));
                    }
                    other => panic!("expected While; got {:?}", other),
                }
            }
            other => panic!("expected Seq; got {:?}", other),
        }
    }

    #[test]
    fn region_blocks_cover_every_llir_block() {
        // Structural analysis must never silently drop blocks — the Region
        // tree's coverage should match the function's block count modulo
        // ordering. (Duplicates are allowed because join blocks appear both
        // inside the conditional and as the subsequent Seq step.)
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100, 0x1200]),
            (0x1100, vec![Op::Nop], vec![0x1300]),
            (0x1200, vec![Op::Nop], vec![0x1300]),
            (0x1300, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        let seen: std::collections::HashSet<usize> = r.blocks().into_iter().collect();
        for i in 0..lf.blocks.len() {
            assert!(seen.contains(&i), "region tree missed block {i}: {:#?}", r);
        }
    }

    #[test]
    fn if_then_with_early_return_no_goto() {
        // The canonical `if (cond) return;` shape:
        //   B0 cond → B1 (terminating arm, returns), B2 (continuation)
        //   B1: return  (no successors)
        //   B2: return  (the function tail)
        // Expected: Seq[ IfThen{cond=0, then=Block(1), join=None}, Block(2) ]
        // Before #192 this fell through to Unstructured because B1 had zero
        // successors and the structurer required the body arm to reach a
        // shared join.
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100, 0x1200]),
            (0x1100, vec![Op::Return], vec![]),
            (0x1200, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        match r {
            Region::Seq(parts) => {
                assert_eq!(parts.len(), 2);
                match &parts[0] {
                    Region::IfThen { cond, then_r, join } => {
                        assert_eq!(*cond, 0);
                        assert!(matches!(**then_r, Region::Block(1)));
                        assert_eq!(*join, None);
                    }
                    other => panic!("expected IfThen with join=None; got {:?}", other),
                }
                assert_eq!(parts[1], Region::Block(2));
            }
            other => panic!("expected Seq; got {:?}", other),
        }
    }

    #[test]
    fn if_then_else_both_arms_terminate() {
        //   B0 cond → B1 (return), B2 (return)
        //   No continuation. Both arms exit the function.
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100, 0x1200]),
            (0x1100, vec![Op::Return], vec![]),
            (0x1200, vec![Op::Return], vec![]),
        ]);
        // Force "both terminate" by NOT using the early-return single-arm
        // pattern. The single-arm pattern fires first because it iterates
        // (t,e) and (e,t); to test the both-terminate branch in isolation
        // we use a CFG where neither arm is the structural continuation.
        // Since both early-return patterns produce equivalent output for a
        // 2-arm leaf, this test mirrors `if_then_with_early_return_no_goto`
        // to keep the contract covered. The both-terminate branch is the
        // safety net for irreducible cases.
        let r = recover_for(&lf);
        // Either Seq[IfThen, Block] or Seq[IfThenElse{join=None}] depending
        // on which detector fires first; both are correct shapes that
        // structure the goto away.
        let blocks: std::collections::HashSet<usize> = r.blocks().into_iter().collect();
        assert!(blocks.contains(&0));
        assert!(blocks.contains(&1));
        assert!(blocks.contains(&2));
        // Most importantly, the recovered region is NOT Unstructured.
        assert!(
            !matches!(&r, Region::Unstructured(_)),
            "expected structured shape; got {:?}", r,
        );
    }

    #[test]
    fn shared_exit_goto_folds_into_if_thens() {
        // The canonical real-binary shape:
        //   B0: cond → B1, L (goto L on true)
        //   B1: cond → B2, L (goto L on true)
        //   B2: → L  (fall-through)
        //   L:  return
        // Expected: the structurer wraps each `if cond` around `Block(L)`
        // and emits L itself as the function tail. Crucially, no
        // Unstructured nodes — every block participates in a structured
        // shape.
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100, 0x1300]), // B0: cond → B1, L
            (0x1100, vec![Op::Nop], vec![0x1200, 0x1300]), // B1: cond → B2, L
            (0x1200, vec![Op::Nop], vec![0x1300]),         // B2: → L
            (0x1300, vec![Op::Return], vec![]),            // L:  return
        ]);
        let r = recover_for(&lf);
        // Walk the tree and confirm no Unstructured leaves and that the
        // shared exit (block 3) is referenced more than once (the
        // clone-inline behaviour).
        fn count_block(r: &Region, target: usize) -> (usize, bool) {
            match r {
                Region::Block(b) => ((*b == target) as usize, false),
                Region::Seq(parts) => {
                    let mut count = 0;
                    let mut bad = false;
                    for p in parts {
                        let (c, b) = count_block(p, target);
                        count += c; bad |= b;
                    }
                    (count, bad)
                }
                Region::IfThen { then_r, .. } => count_block(then_r, target),
                Region::IfThenElse { then_r, else_r, .. } => {
                    let (c1, b1) = count_block(then_r, target);
                    let (c2, b2) = count_block(else_r, target);
                    (c1 + c2, b1 || b2)
                }
                Region::While { body, .. } => count_block(body, target),
                Region::Unstructured(_) => (0, true),
            }
        }
        let (count, has_unstructured) = count_block(&r, 3);
        assert!(!has_unstructured, "expected no Unstructured; got {:?}", r);
        assert!(count >= 2, "expected shared-exit block referenced >=2 times; got {} in {:?}", count, r);
    }

    #[test]
    fn nested_early_returns_chain_into_seq() {
        //   B0 cond → B1 (return), B2 (next test)
        //   B2 cond → B3 (return), B4 (return)
        // Expected: two IfThens fused into a Seq, no Unstructured leaves.
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100, 0x1200]),
            (0x1100, vec![Op::Return], vec![]),
            (0x1200, vec![Op::Nop], vec![0x1300, 0x1400]),
            (0x1300, vec![Op::Return], vec![]),
            (0x1400, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        // No Unstructured anywhere in the tree.
        fn assert_no_unstructured(r: &Region) {
            match r {
                Region::Block(_) => {}
                Region::Seq(parts) => parts.iter().for_each(assert_no_unstructured),
                Region::IfThen { then_r, .. } => assert_no_unstructured(then_r),
                Region::IfThenElse { then_r, else_r, .. } => {
                    assert_no_unstructured(then_r);
                    assert_no_unstructured(else_r);
                }
                Region::While { body, .. } => assert_no_unstructured(body),
                Region::Unstructured(bs) => panic!("found Unstructured: {:?}", bs),
            }
        }
        assert_no_unstructured(&r);
        // All five blocks must still be covered.
        let blocks: std::collections::HashSet<usize> = r.blocks().into_iter().collect();
        for i in 0..5 {
            assert!(blocks.contains(&i), "block {} missing", i);
        }
    }

    #[test]
    fn runs_on_real_binary_without_losing_blocks() {
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
                let ssa = compute_ssa(&lf);
                let r = recover(&lf, &ssa);
                // Every block must be covered at least once.
                let covered: std::collections::HashSet<usize> =
                    r.blocks().into_iter().collect();
                for i in 0..lf.blocks.len() {
                    assert!(
                        covered.contains(&i),
                        "block {} missing from region tree of {}",
                        i,
                        f.name,
                    );
                }
            }
        }
    }
}
