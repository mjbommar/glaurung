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
//! * Natural loops with a single back-edge and a single header (`While` and
//!   `DoWhile`).
//! * Anything else is preserved as [`Region::Unstructured`] carrying the raw
//!   block indices so no control flow is ever silently dropped.
//!
//! The algorithm walks the CFG from the entry block, pattern-matching on
//! successor counts and dominator info. It is intentionally simple and
//! conservative; irreducible or heavily goto-laden code degrades gracefully
//! to `Unstructured`.
//!
//! # Where the pieces live
//!
//! This file is the **recovery driver**: the public entry points, the
//! recursive `build`/`build_arm` walk that assembles the tree, and
//! `build_full`, which decides what the caller is actually handed. Every
//! other concern is one module below it, each with one reason to change:
//!
//! * `region` — the [`Region`] tree itself and the two queries answerable
//!   from it alone. Changes when the region algebra grows a shape.
//! * `cfg` — the derived-facts view of the graph, built once per call:
//!   dominators, post-dominators, typed edges, the reachability closure and
//!   the natural-loop memos. Changes when a new fact is needed, or an old one
//!   gets cheaper.
//! * `loop_shape`, `switch_shape`, `if_shape` — the three recognisers
//!   `build` tries, one per shape. Each changes when its own shape does.
//! * `path_predicates` — the "may I?" proofs those recognisers ask before
//!   committing.
//! * `fallback` — the policy that rejects a speculative tree in favour of
//!   the labelled CFG. Changes when the algebra can express one more shape.
//! * `verify` — the well-formedness contract, pure over a successor
//!   relation and blind to how the tree was built.

use std::collections::HashSet;

use crate::ir::ssa::SsaInfo;
use crate::ir::types::LlirFunction;

mod cfg;
mod fallback;
mod if_shape;
mod loop_shape;
mod path_predicates;
mod region;
mod switch_shape;
mod verify;

pub(crate) use cfg::{BranchPredicate, Cfg};
use fallback::{
    contains_structured_loop, contains_switch, has_inner_loop_exit_that_reenters_via_outer_cycle,
    has_loop_conditional_with_join_beyond_loop, has_multi_latch_loop_with_distinct_exits,
    structure_accounting_is_unsound,
};
use if_shape::detect_if_shape;
use loop_shape::{
    detect_bottom_tested_loop, detect_natural_loop, detect_raw_dispatch_loop,
    detect_raw_multi_latch_loop, has_dispatch_natural_loop, loop_break_shape,
};
pub use region::{entry_block, Region};
use switch_shape::{detect_guarded_switch_shape, detect_switch_shape};
pub use verify::{verify_region, StructError};
// `find_switch_join` has no caller outside `switch_shape` itself except `mod
// tests` below, which reaches it through `use super::*`. Re-exporting it
// unconditionally would be an unused import in the shipped lib build.
#[cfg(test)]
use switch_shape::find_switch_join;

/// Single public entry point — build a region tree for the function.
pub fn recover(lf: &LlirFunction, ssa: &SsaInfo) -> Region {
    if lf.blocks.is_empty() {
        return Region::Unstructured(Vec::new());
    }
    let cfg = Cfg::from(lf, ssa);
    build_full(lf, &cfg)
}

fn flatten_seq(r: Region) -> Vec<Region> {
    match r {
        Region::Seq(parts) => parts,
        other => vec![other],
    }
}

/// Verify the region tree [`recover`] produces for `lf`. Empty == the structure
/// faithfully covers every reachable block and conditional edge.
pub fn verify_structure(lf: &LlirFunction, ssa: &SsaInfo) -> Vec<StructError> {
    if lf.blocks.is_empty() {
        return Vec::new();
    }
    let cfg = Cfg::from(lf, ssa);
    let region = recover(lf, ssa);
    verify_region(&cfg.succs, 0, &region)
}

/// [`recover`] plus a structural self-check. A region which drops a real block or
/// edge, invents an edge, leaves a back-edge without a loop owner, leaves a goto
/// dangling, or moves a switch arm outside its loop is not safe to render:
/// production recovery falls back to the complete labelled CFG. Weaker quality
/// findings (an explicit goto or deliberate cloning of a shared terminal block)
/// remain diagnostics because they still express executable control flow. This is
/// the single production entry the decompile paths should call.
pub fn recover_verified(lf: &LlirFunction, ssa: &SsaInfo) -> Region {
    recover_verified_with_health(lf, ssa).0
}

/// [`recover_verified`] plus immutable fidelity counters for the selected output.
///
/// Candidate findings are used to decide whether to fall back. The returned edge
/// counts describe the region that will actually be lowered; a separate fallback
/// counter keeps a rejected speculative structure visible without falsely claiming
/// that labelled-CFG output dropped or invented its edges.
pub fn recover_verified_with_health(
    lf: &LlirFunction,
    ssa: &SsaInfo,
) -> (Region, crate::ir::health::CfgHealth) {
    recover_verified_with_health_and_destinations(lf, ssa, &std::collections::BTreeMap::new())
}

/// [`recover_verified_with_health`] told what a relocation proves about each
/// computed transfer.
///
/// The region recovery is identical — `destinations` reaches only the terminal
/// census, which is a diagnostic. It is threaded here rather than derived here
/// because the proof needs the image's relocation tables and this module sees
/// only the lifted function; see [`crate::ir::indirect_targets`].
pub fn recover_verified_with_health_and_destinations(
    lf: &LlirFunction,
    ssa: &SsaInfo,
    destinations: &std::collections::BTreeMap<
        u64,
        crate::ir::indirect_targets::IndirectDestination,
    >,
) -> (Region, crate::ir::health::CfgHealth) {
    let cfg = Cfg::from(lf, ssa);
    #[cfg(feature = "structure-v2-shadow")]
    {
        let shadow = crate::ir::structure_v2::observe_cfg(&cfg, lf);
        tracing::debug!(
            entry_va = format_args!("{:#x}", lf.entry_va),
            blocks = shadow.block_count,
            edges = shadow.edge_count,
            covered_blocks = shadow.covered_blocks,
            represented_edges = shadow.represented_edges,
            refusal = ?shadow.refusal,
            "structure v2 shadow observation"
        );
    }
    let region = build_full(lf, &cfg);
    let errors = verify_region(&cfg.succs, 0, &region);
    if !errors.is_empty() {
        tracing::debug!(
            entry_va = format_args!("{:#x}", lf.entry_va),
            count = errors.len(),
            "structure verifier: {} unfaithful region(s): {:?}",
            errors.len(),
            errors
        );
    }
    // Account every typed edge in both directions. The older block/arm verifier
    // is silent on conditional latches whose taken edge repeats the loop while
    // the fallthrough exits: lowering strips the back-edge and used to leave an
    // empty `if`, making the loop unconditional. A labelled CFG is less pretty
    // than a speculative While, but it is the only semantics-preserving result.
    let acct = crate::ir::structure_accounting::account(&cfg.edges, &cfg.preds, 0, &region);
    let is_unsound = structure_accounting_is_unsound(&acct);
    let region_is_fallback = !lf.blocks.is_empty()
        && matches!(&region, Region::Unstructured(blocks) if blocks.len() == lf.blocks.len());
    if std::env::var_os("GLAURUNG_ACCOUNT_STRUCTURE").is_some() && !acct.is_empty() {
        // stderr, not `tracing`: no subscriber is installed on the CLI or PyO3
        // paths, so a `tracing::warn!` here reached nobody — a diagnostic that
        // cannot be read is not a diagnostic. Matches `GLAURUNG_DUMP_PASSES`.
        eprintln!(
            "[account] {:#x}: {} finding(s): {:?}",
            lf.entry_va,
            acct.len(),
            acct
        );
    }
    let selected = if is_unsound {
        Region::Unstructured((0..lf.blocks.len()).collect())
    } else {
        region
    };
    let selected_accounting = if is_unsound {
        crate::ir::structure_accounting::account(&cfg.edges, &cfg.preds, 0, &selected)
    } else {
        acct
    };
    // The region accounting above says what the tree failed to express about this
    // graph. The census below says what the graph failed to prove about the
    // program: an unresolved dispatch, a transfer no terminator explains, a block
    // that leaves the function by no route we can name. A region can account
    // perfectly for a graph that is missing half the control flow, so both counts
    // travel together or neither is worth reading.
    let terminals =
        crate::ir::cfg_edges::classify_terminals_with_destinations(lf, &cfg.succs, destinations);
    let health = crate::ir::health::cfg_health_from_accounting(
        &selected_accounting,
        region_is_fallback || is_unsound,
    )
    .with_edge_census(&cfg.edges, &terminals);
    (selected, health)
}

/// The block-losing-leftover-aware region build shared by [`recover`] and
/// [`recover_verified`], so both see the identical tree.
fn build_full(lf: &LlirFunction, cfg: &Cfg) -> Region {
    if lf.blocks.is_empty() {
        return Region::Unstructured(Vec::new());
    }
    // `While` can represent one distinguished exit reached from its header.
    // A rotated multi-latch loop may instead have an early-return edge from
    // the header *and* a different normal-exhaustion edge from its latches.
    // Forcing that graph into `While` silently moves one set of blocks below
    // the other return (clang -O2 binary search was the real canary).  Preserve
    // the complete labelled CFG until the region algebra grows owned multi-
    // exits; `Unstructured` is explicitly the lossless fallback contract.
    let has_dispatch_loop_fallback =
        (0..cfg.succs.len()).any(|header| has_dispatch_natural_loop(header, cfg));
    let has_multi_latch_distinct_exits = has_multi_latch_loop_with_distinct_exits(cfg);
    let has_conditional_join_beyond_loop = has_loop_conditional_with_join_beyond_loop(cfg);
    let has_inner_reentry = has_inner_loop_exit_that_reenters_via_outer_cycle(cfg);
    if !has_dispatch_loop_fallback
        && (has_multi_latch_distinct_exits || has_conditional_join_beyond_loop || has_inner_reentry)
    {
        return Region::Unstructured((0..lf.blocks.len()).collect());
    }
    let mut visited: HashSet<usize> = HashSet::new();
    let region = build(0, cfg, &mut visited, None);
    let leftover: Vec<usize> = (0..lf.blocks.len())
        .filter(|b| !visited.contains(b))
        .collect();
    let has_leftover = !leftover.is_empty();
    let region = if !has_leftover {
        region
    } else {
        let mut parts = flatten_seq(region);
        parts.push(Region::Unstructured(leftover));
        Region::Seq(parts)
    };
    // A structured loop followed by leftovers is only safe when every loop
    // edge is still represented.  In an unrolled early-return ladder the body
    // builder can stop at an internal conditional, leave the latch in the
    // leftovers, and nevertheless satisfy the older block-only verifier.  The
    // typed-edge accountant detects both the missing fallthrough/back-edge and
    // the invented loop exits.  Fall back to the complete labelled CFG rather
    // than emitting a partial While followed by unreachable blocks.
    let leftover_accounting_is_unsound = has_leftover
        && contains_structured_loop(&region)
        && !contains_switch(&region)
        && structure_accounting_is_unsound(&crate::ir::structure_accounting::account(
            &cfg.edges, &cfg.preds, 0, &region,
        ));
    if leftover_accounting_is_unsound {
        Region::Unstructured((0..lf.blocks.len()).collect())
    } else {
        region
    }
}

/// Recursively build a Region starting at `start`, stopping at `stop_at`
/// (exclusive). `visited` tracks blocks consumed into the output.
fn build(start: usize, cfg: &Cfg, visited: &mut HashSet<usize>, stop_at: Option<usize>) -> Region {
    let mut parts: Vec<Region> = Vec::new();
    let mut cur = start;

    loop {
        if Some(cur) == stop_at {
            break;
        }
        if visited.contains(&cur) {
            // Already consumed — avoid infinite loops on back-edges or shared
            // successors we don't currently model structurally.
            break;
        }

        // A compiler state machine can use its jump-table dispatch, or the
        // range guard immediately before it, as the natural-loop header. No
        // one case is a source-level loop condition. Detect this before a
        // bottom-tested loop can wrap the raw dispatch body and claim one of
        // its internal case blocks as a distinguished latch.
        if let Some(loop_r) = detect_raw_dispatch_loop(cur, cfg, visited) {
            parts.push(loop_r.region);
            match loop_r.exit {
                Some(next) => {
                    cur = next;
                    continue;
                }
                None => break,
            }
        }

        // --- Bottom-tested natural loop ------------------------------------
        // Detect this before inserting `cur` into `visited`: the recovered body
        // begins at `cur` and must be structured recursively up to (but not
        // including) the conditional latch.
        if let Some(loop_r) = detect_bottom_tested_loop(cur, cfg, visited) {
            parts.push(loop_r.region);
            match loop_r.exit {
                Some(next) => {
                    cur = next;
                    continue;
                }
                None => break,
            }
        }

        // Multiple conditional latches can share one exit while the header is
        // only an internal dispatch. No single condition represents that loop;
        // retain its exact labelled CFG inside an owned `while (1)` region.
        if let Some(loop_r) = detect_raw_multi_latch_loop(cur, cfg, visited) {
            parts.push(loop_r.region);
            match loop_r.exit {
                Some(next) => {
                    cur = next;
                    continue;
                }
                None => break,
            }
        }

        // `detect_bottom_tested_loop` needs an unconsumed body entry. All other
        // shapes retain the original consume-before-detect behaviour.
        if !visited.insert(cur) {
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

        // --- Switch shape (#193) -------------------------------------------
        // Typed dispatch identity wins over graph out-degree. Compiler case
        // folding can leave a four-slot indirect table with only two distinct
        // destination blocks; treating that graph as an if/else loses the
        // switch expression and half its labels.
        if cfg.is_switch_dispatch(cur) {
            if let Some((sw, after)) = detect_switch_shape(cur, cfg, visited, stop_at) {
                parts.push(sw);
                match after {
                    Some(next) => {
                        cur = next;
                        continue;
                    }
                    None => break,
                }
            }
        }

        // --- Conditional shapes ---------------------------------------------
        if cfg.succs[cur].len() == 2 {
            // While building a natural-loop body, an edge directly to the
            // header's distinguished exit is a lossless `break` shape. Consume
            // the conditional here and continue down its body sibling instead
            // of letting global post-dominance absorb the exit epilogue as a
            // local join and strand the rest of the loop as leftovers.
            if let Some(header) = stop_at {
                if let Some((exit, continuation, break_entry, invert)) =
                    loop_break_shape(cur, header, cfg)
                {
                    let break_region = if break_entry == exit {
                        Region::Goto(exit)
                    } else {
                        build(break_entry, cfg, visited, Some(exit))
                    };
                    parts.push(Region::IfThen {
                        cond: cur,
                        then_r: Box::new(break_region),
                        join: None,
                        invert,
                    });
                    cur = continuation;
                    continue;
                }
            }
            // Resolved switches are collapsed before their surrounding range
            // guard in Ghidra, angr Phoenix, and Kuna. Doing the same here is
            // required when the default path shares a terminal tail with one
            // explicit case: ordinary if/else ownership cannot represent that
            // overlap without either duplicating or dropping the tail.
            if let Some((sw, after)) = detect_guarded_switch_shape(cur, cfg, visited, stop_at) {
                parts.push(sw);
                match after {
                    Some(next) => {
                        cur = next;
                        continue;
                    }
                    None => break,
                }
            }
            if let Some((ite, after)) = detect_if_shape(cur, cfg, visited, stop_at) {
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
            // A conditional that did not fit a high-level shape still lowers
            // its taken edge from the machine CondJump. Its fallthrough edge,
            // however, exists only by source adjacency. Once this builder stops
            // at the unstructured conditional, no region owns that adjacency;
            // materialise it as a goto whether its shared target was built by a
            // sibling already or will be built later.
            if succs.len() == 2 {
                if let Some(fallthrough) = cfg.edges[cur]
                    .iter()
                    .find(|edge| {
                        edge.kind == crate::ir::cfg_edges::EdgeKind::Fallthrough
                            && Some(edge.to) != stop_at
                    })
                    .map(|edge| edge.to)
                {
                    parts.push(Region::Goto(fallthrough));
                }
            }
            break;
        }
        let next = succs[0];
        if Some(next) == stop_at {
            break;
        }
        if visited.contains(&next) {
            // An explicit machine jump is already present in `Block(cur)` and
            // lowers to a C goto.  A LINEAR edge has no instruction to carry
            // it: once structuring relocates `cur` away from the block that
            // previously followed it in memory, silently stopping here drops
            // control flow. Materialise only that adjacency edge as a region
            // goto to the already-owned block.
            if cfg.edges[cur]
                .iter()
                .any(|edge| edge.to == next && edge.kind == crate::ir::cfg_edges::EdgeKind::Linear)
            {
                parts.push(Region::Goto(next));
            }
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

/// Build a conditional *arm* starting at `entry`. Identical to [`build`] except
/// that when `entry` has already been consumed by a sibling (a *shared* join
/// block, e.g. the common false block of `a && b`) we emit an explicit
/// [`Region::Goto`] to it rather than letting [`build`] hit its visited-guard and
/// return an empty region — which silently drops the edge (the short-circuit
/// empty-arm bug). `stop_at` (the join) is never gotoed; it is emitted after the
/// conditional.
fn build_arm(
    entry: usize,
    cfg: &Cfg,
    visited: &mut HashSet<usize>,
    stop_at: Option<usize>,
) -> Region {
    if Some(entry) != stop_at && visited.contains(&entry) {
        return Region::Goto(entry);
    }
    build(entry, cfg, visited, stop_at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ssa::compute_ssa;
    use crate::ir::types::{LlirBlock, LlirInstr, Op, VReg, Value};

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
    fn duplicate_jump_table_targets_keep_every_case_label() {
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![Op::IndirectJump {
                    target: Value::Reg(VReg::phys("target")),
                    index: Some(Value::Reg(VReg::phys("index"))),
                }],
                vec![
                    0x1100, 0x1200, 0x1300, 0x1400, 0x1500, 0x1300, 0x1600, 0x1700,
                ],
            ),
            (0x1100, vec![Op::Return], vec![]),
            (0x1200, vec![Op::Return], vec![]),
            (0x1300, vec![Op::Return], vec![]),
            (0x1400, vec![Op::Return], vec![]),
            (0x1500, vec![Op::Return], vec![]),
            (0x1600, vec![Op::Return], vec![]),
            (0x1700, vec![Op::Return], vec![]),
        ]);

        let region = recover_for(&lf);
        let Region::Switch {
            arms, case_labels, ..
        } = region
        else {
            panic!("expected a switch, got {region:#?}");
        };

        assert_eq!(arms.len(), 7, "one body per distinct destination");
        assert_eq!(
            case_labels,
            vec![
                vec![0],
                vec![1],
                vec![2, 5],
                vec![3],
                vec![4],
                vec![6],
                vec![7],
            ],
            "the shared body must retain both table indices"
        );
    }

    #[test]
    fn a_four_slot_table_with_two_unique_bodies_still_structures_as_a_switch() {
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![Op::IndirectJump {
                    target: Value::Reg(VReg::phys("target")),
                    index: Some(Value::Reg(VReg::phys("index"))),
                }],
                vec![0x1100, 0x1200, 0x1100, 0x1200],
            ),
            (0x1100, vec![Op::Return], vec![]),
            (0x1200, vec![Op::Return], vec![]),
        ]);

        let region = recover_verified(&lf, &compute_ssa(&lf));
        let Region::Switch {
            arms, case_labels, ..
        } = region
        else {
            panic!("expected a shared-body switch, got {region:#?}");
        };

        assert_eq!(arms.len(), 2);
        assert_eq!(case_labels, vec![vec![0, 2], vec![1, 3]]);
    }

    #[test]
    fn switch_cases_may_fall_through_into_later_case_entries() {
        // Real Clang 14 -O2 shape for `fallthrough_chain`: every table slot is
        // an entry into one suffix of a shared linear chain.  The later case
        // blocks therefore have both the dispatch and the previous case as
        // predecessors; that is case fallthrough, not ambiguous ownership.
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![Op::IndirectJump {
                    target: Value::Reg(VReg::phys("target")),
                    index: Some(Value::Reg(VReg::phys("index"))),
                }],
                vec![0x1100, 0x1200, 0x1300, 0x1400],
            ),
            (0x1100, vec![Op::Nop], vec![0x1200]),
            (0x1200, vec![Op::Nop], vec![0x1300]),
            (0x1300, vec![Op::Nop], vec![0x1400]),
            (0x1400, vec![Op::Return], vec![]),
        ]);

        let region = recover_for(&lf);
        let Region::Switch {
            arms, case_labels, ..
        } = &region
        else {
            panic!("expected a fallthrough switch, got {region:#?}");
        };
        assert_eq!(arms.len(), 4);
        assert_eq!(case_labels, &vec![vec![0], vec![1], vec![2], vec![3]]);
        assert!(
            verify_region(
                &lf.blocks
                    .iter()
                    .map(|block| {
                        block
                            .succs
                            .iter()
                            .map(|target| {
                                lf.blocks
                                    .iter()
                                    .position(|candidate| candidate.start_va == *target)
                                    .expect("successor belongs to test CFG")
                            })
                            .collect()
                    })
                    .collect::<Vec<Vec<usize>>>(),
                0,
                &region,
            )
            .is_empty(),
            "fallthrough switch must retain every reachable block: {region:#?}"
        );
    }

    /// Characterises the largest measured structuring gap: a chain of
    /// `if (c) { handler; }` guards whose handlers are emitted OUT OF LINE.
    ///
    /// Transcribed edge-for-edge from `bin_090.elf` `sub_7370` in the frozen
    /// DecBench sample-set — 15 blocks, of which the renderer labels 12. Over
    /// the 250 scored sample-set functions, 28.8% render as goto soup (40.5% on
    /// x86-64), and only 2.6% of those are whole-function bailouts, so the loss
    /// is `detect_if_shape` declining shape by shape and taking the rest of the
    /// walk with it. This is the smallest instance.
    ///
    /// **This test pins the CURRENT, WRONG behaviour.** If it fails because the
    /// numbers went DOWN, the gap is closing: read the new region, confirm it,
    /// and update the expectation.
    ///
    /// # A local fix was tried here and reverted, on measurement
    ///
    /// `shared_return_chain` refuses any chain whose entry has one predecessor,
    /// so an EXCLUSIVELY OWNED multi-block chain to a return has no owner: a
    /// single terminal block is the early-exit shape, a shared chain is the
    /// clone shape, and this falls between them. Admitting it (as
    /// `linear_return_chain`, guarded so the two arms must genuinely diverge)
    /// takes this reproduction from nine unstructured blocks to one and keeps
    /// all 91 structure tests green.
    ///
    /// It was still reverted, because that is not the whole measurement:
    ///
    /// * it does **not** move the corpus — `sub_7370` itself stays at 12 labels
    ///   and the 250-function census is flat on x86-64 (65 structured / 64 goto
    ///   soup, before and after), because the LLIR CFG these functions are
    ///   structured from is not the analysis CFG this test transcribes
    ///   (`lift_function` clips blocks to owned ranges and prunes edges); and
    /// * it **costs correctness**: `tools/gen_defuse_baseline.py` reports
    ///   `rustc:O0` +15 and `rustc:O2` +11 undefined reads, in fixture lanes
    ///   that were already tracked. Each is a wrong-code bug — the recovered
    ///   function reads a value the machine never produced.
    ///
    /// That is the third local fix to this function to be reverted after
    /// measurement, and the third for the same reason: widening one predicate
    /// trades one shape for another. The answer is the region analysis
    /// `docs/history/design/campaigns/decbench-defect-reproductions-2026-08-27.md` §7 P3
    /// specifies — a loop forest computed once, a region context replacing
    /// `stop_at`, and a loop-relative join oracle — not a fourth predicate.
    #[test]
    fn out_of_line_guard_handlers_are_still_lost_to_goto() {
        let cond = || {
            vec![Op::CondJump {
                cond: VReg::Flag(crate::ir::types::Flag::Z),
                target: 0,
                inverted: false,
            }]
        };
        let lf = mk_cfg(vec![
            // (block, ops, [handler, fallthrough]) — handler first, exactly as
            // the real function reports it.
            (0x1000, cond(), vec![0x2000, 0x1100]), // A, handler H1 rejoins B
            (0x1100, cond(), vec![0x2100, 0x1200]), // B, handler H2 rejoins C
            (0x1200, cond(), vec![0x3000, 0x1300]), // C, early exit to X
            (0x1300, cond(), vec![0x2200, 0x1400]), // D, handler H3 EXITS via X
            (0x1400, cond(), vec![0x2300, 0x1500]), // E, handler H4 rejoins F
            (0x1500, cond(), vec![0x2400, 0x1600]), // F, handler H5 rejoins G
            (0x1600, cond(), vec![0x2500, 0x1700]), // G, handler H6 rejoins R
            (0x1700, vec![Op::Return], vec![]),     // R
            (0x2000, vec![Op::Jump { target: 0x1100 }], vec![0x1100]),
            (0x2100, vec![Op::Jump { target: 0x1200 }], vec![0x1200]),
            (0x2200, vec![Op::Jump { target: 0x3000 }], vec![0x3000]),
            (0x2300, vec![Op::Jump { target: 0x1500 }], vec![0x1500]),
            (0x2400, vec![Op::Jump { target: 0x1600 }], vec![0x1600]),
            (0x2500, vec![Op::Jump { target: 0x1700 }], vec![0x1700]),
            (0x3000, vec![Op::Return], vec![]), // X, the shared epilogue
        ]);

        let region = recover_for(&lf);

        fn tally(region: &Region, ifs: &mut usize, gotos: &mut usize, loose: &mut usize) {
            match region {
                Region::IfThen { then_r, .. } => {
                    *ifs += 1;
                    tally(then_r, ifs, gotos, loose);
                }
                Region::IfThenElse { then_r, else_r, .. } => {
                    *ifs += 1;
                    tally(then_r, ifs, gotos, loose);
                    tally(else_r, ifs, gotos, loose);
                }
                Region::Seq(parts) => {
                    for part in parts {
                        tally(part, ifs, gotos, loose);
                    }
                }
                Region::While { body, .. }
                | Region::DoWhile { body, .. }
                | Region::MultiExitLoop { body, .. } => tally(body, ifs, gotos, loose),
                Region::Switch { arms, .. } => {
                    for arm in arms {
                        tally(arm, ifs, gotos, loose);
                    }
                }
                Region::Goto(_) => *gotos += 1,
                Region::Unstructured(blocks) => *loose += blocks.len(),
                Region::Block(_) | Region::RawLoop { .. } => {}
            }
        }
        let (mut ifs, mut gotos, mut loose) = (0usize, 0usize, 0usize);
        tally(&region, &mut ifs, &mut gotos, &mut loose);

        assert_eq!(
            (ifs, loose),
            (3, 9),
            "seven conditionals, of which three structure and the rest are lost \
             from the fourth onward. A LOWER `loose` means the gap is closing — \
             read the region, confirm it, and update this expectation: {region:#?}"
        );
        assert_eq!(gotos, 0, "the loss is Unstructured, not Goto: {region:#?}");
    }

    #[test]
    fn a_guard_default_reused_by_table_holes_is_a_formal_switch_default() {
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![Op::CondJump {
                    cond: VReg::Flag(crate::ir::types::Flag::C),
                    target: 0x1400,
                    inverted: false,
                }],
                vec![0x1100, 0x1400],
            ),
            (
                0x1100,
                vec![Op::IndirectJump {
                    target: Value::Reg(VReg::phys("target")),
                    index: Some(Value::Reg(VReg::phys("index"))),
                }],
                vec![0x1200, 0x1400, 0x1200, 0x1400, 0x1300, 0x1300],
            ),
            (0x1200, vec![Op::Jump { target: 0x1500 }], vec![0x1500]),
            (0x1300, vec![Op::Jump { target: 0x1500 }], vec![0x1500]),
            (0x1400, vec![Op::Jump { target: 0x1500 }], vec![0x1500]),
            (0x1500, vec![Op::Return], vec![]),
        ]);

        let region = recover_for(&lf);
        fn find_switch(region: &Region) -> Option<(&[Vec<i64>], Option<&Region>)> {
            match region {
                Region::Switch {
                    case_labels,
                    formal_default,
                    ..
                } => Some((case_labels, formal_default.as_deref())),
                Region::Seq(parts) => parts.iter().find_map(find_switch),
                Region::IfThen { then_r, .. } => find_switch(then_r),
                Region::IfThenElse { then_r, else_r, .. } => {
                    find_switch(then_r).or_else(|| find_switch(else_r))
                }
                Region::While { body, .. }
                | Region::DoWhile { body, .. }
                | Region::MultiExitLoop { body, .. } => find_switch(body),
                Region::Block(_)
                | Region::Goto(_)
                | Region::RawLoop { .. }
                | Region::Unstructured(_) => None,
            }
        }

        let (labels, formal_default) =
            find_switch(&region).unwrap_or_else(|| panic!("expected switch: {region:#?}"));
        assert_eq!(labels, [vec![0, 2], vec![4, 5]]);
        assert!(
            formal_default.is_some_and(|default| default.blocks().contains(&4)),
            "the guard/table shared target must be the formal default: {region:#?}"
        );
    }

    #[test]
    fn a_dense_guarded_switch_keeps_its_out_of_table_default() {
        // Canonical dense-table shape: the range guard's out-of-range target
        // is not itself a table entry.  Its typed SwitchDefault edge is still
        // part of the switch and must not be lost at function scope.
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![
                    Op::Cmp {
                        dst: VReg::Flag(crate::ir::types::Flag::C),
                        op: crate::ir::types::CmpOp::Ule,
                        lhs: Value::Reg(VReg::phys("index")),
                        rhs: Value::Const(1),
                    },
                    Op::CondJump {
                        cond: VReg::Flag(crate::ir::types::Flag::C),
                        target: 0x1400,
                        inverted: true,
                    },
                ],
                vec![0x1100, 0x1400],
            ),
            (
                0x1100,
                vec![Op::IndirectJump {
                    target: Value::Reg(VReg::phys("target")),
                    index: Some(Value::Reg(VReg::phys("index"))),
                }],
                vec![0x1200, 0x1300],
            ),
            (0x1200, vec![Op::Return], vec![]),
            (0x1300, vec![Op::Return], vec![]),
            (0x1400, vec![Op::Return], vec![]),
        ]);

        let ssa = compute_ssa(&lf);
        let region = recover_verified(&lf, &ssa);
        let Region::Switch {
            guard: Some(0),
            case_labels,
            formal_default: Some(default),
            ..
        } = &region
        else {
            panic!("expected a dense guarded switch, got {region:#?}");
        };
        assert_eq!(case_labels, &[vec![0], vec![1]]);
        assert!(default.blocks().contains(&4), "{region:#?}");
        assert!(
            verify_structure(&lf, &ssa).is_empty(),
            "dense guard/default edge must remain represented: {region:#?}"
        );
        let cfg = Cfg::from(&lf, &ssa);
        assert!(
            crate::ir::structure_accounting::account(&cfg.edges, &cfg.preds, 0, &region).is_empty(),
            "dense guarded switch must account for every typed edge: {region:#?}"
        );
    }

    #[test]
    fn guarded_switch_default_shared_by_case_paths_keeps_both_guard_edges() {
        // Reduced from NuttX O2-noinline `nxsig_find_pendingsignal`.  The range
        // guard and jump-table holes enter b3 directly, while every explicit
        // case also flows through b3 before the common continuation b6.  Case
        // recovery must not consume b3 before the formal default is built.
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![Op::CondJump {
                    cond: VReg::Flag(crate::ir::types::Flag::C),
                    target: 0x1300,
                    inverted: false,
                }],
                vec![0x1100, 0x1300],
            ),
            (
                0x1100,
                vec![Op::IndirectJump {
                    target: Value::Reg(VReg::phys("target")),
                    index: Some(Value::Reg(VReg::phys("index"))),
                }],
                vec![0x1200, 0x1300, 0x1400, 0x1300],
            ),
            (0x1200, vec![Op::Jump { target: 0x1300 }], vec![0x1300]),
            (
                0x1300,
                vec![Op::CondJump {
                    cond: VReg::Flag(crate::ir::types::Flag::Z),
                    target: 0x1500,
                    inverted: false,
                }],
                vec![0x1500, 0x1600],
            ),
            (0x1400, vec![Op::Jump { target: 0x1300 }], vec![0x1300]),
            (0x1500, vec![Op::Jump { target: 0x1600 }], vec![0x1600]),
            (0x1600, vec![Op::Return], vec![]),
        ]);

        let ssa = compute_ssa(&lf);
        let region = recover(&lf, &ssa);
        let errors = verify_structure(&lf, &ssa);
        assert!(
            errors.is_empty(),
            "the guard-to-default edge was lost: {errors:?}\n{region:#?}"
        );

        let Region::Seq(parts) = &region else {
            panic!("expected switch followed by its continuation: {region:#?}")
        };
        let Some(Region::Switch {
            guard: Some(0),
            formal_default: Some(default),
            ..
        }) = parts.first()
        else {
            panic!("expected a guarded switch with a formal default: {region:#?}")
        };
        assert!(
            default.blocks().contains(&3),
            "the formal default must retain the shared target: {region:#?}"
        );
    }

    #[test]
    fn switch_join_prefers_a_shared_continuation_over_an_internal_arm_merge() {
        // Block 5 is an internal merge in case 0; block 8 is the normal switch
        // continuation reached by all three cases. The extra conditional at
        // block 1 gives recursive if lowering a function-level `stop_at` (9),
        // not the surrounding loop header (0). Following the back-edge through
        // block 0 makes every arm appear to reach block 5 and lets its lower
        // address steal ownership from block 8. This is the shape of
        // `05_cleanup_and_state_machine:fsm`.
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![Op::CondJump {
                    cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                    target: 0x1b00,
                    inverted: false,
                }],
                vec![0x1100, 0x1b00],
            ),
            (
                0x1100,
                vec![Op::CondJump {
                    cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::C),
                    target: 0x1a00,
                    inverted: false,
                }],
                vec![0x1200, 0x1a00],
            ),
            (0x1200, vec![Op::Nop], vec![0x1300, 0x1600, 0x1700]),
            (
                0x1300,
                vec![Op::CondJump {
                    cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                    target: 0x1c00,
                    inverted: false,
                }],
                vec![0x1400, 0x1c00],
            ),
            (0x1400, vec![Op::Nop], vec![0x1500]),
            (0x1500, vec![Op::Nop], vec![0x1800]),
            (0x1600, vec![Op::Nop], vec![0x1800]),
            (0x1700, vec![Op::Nop], vec![0x1800]),
            (0x1800, vec![Op::Jump { target: 0x1000 }], vec![0x1000]),
            (0x1900, vec![Op::Return], vec![]),
            (0x1a00, vec![Op::Jump { target: 0x1900 }], vec![0x1900]),
            (0x1b00, vec![Op::Jump { target: 0x1900 }], vec![0x1900]),
            (0x1c00, vec![Op::Jump { target: 0x1900 }], vec![0x1900]),
        ]);
        let ssa = compute_ssa(&lf);
        let cfg = Cfg::from(&lf, &ssa);
        assert_eq!(
            find_switch_join(2, &[3, 6, 7], &cfg, Some(9)),
            Some(8),
            "the shared loop continuation is the join"
        );
        fn find_switch(region: &Region) -> Option<&Region> {
            match region {
                Region::Switch { .. } => Some(region),
                Region::Seq(parts) => parts.iter().find_map(find_switch),
                Region::IfThen { then_r, .. } => find_switch(then_r),
                Region::IfThenElse { then_r, else_r, .. } => {
                    find_switch(then_r).or_else(|| find_switch(else_r))
                }
                Region::While { body, .. }
                | Region::DoWhile { body, .. }
                | Region::MultiExitLoop { body, .. } => find_switch(body),
                Region::Block(_)
                | Region::Goto(_)
                | Region::RawLoop { .. }
                | Region::Unstructured(_) => None,
            }
        }
        let region = recover_for(&lf);
        let Some(Region::Switch { arms, .. }) = find_switch(&region) else {
            panic!("expected recovered switch: {region:?}");
        };
        assert!(
            arms.iter().all(|arm| !arm.blocks().contains(&9)),
            "the shared function epilogue must stay outside the switch: {arms:?}"
        );
        assert!(
            region.blocks().into_iter().any(|block| block == 9),
            "the shared epilogue must remain represented at function scope"
        );
    }

    #[test]
    fn comparison_ladder_recovers_as_nested_if_else() {
        use crate::ir::types::{Flag, VReg};
        let cj = |target: u64| Op::CondJump {
            cond: VReg::Flag(Flag::Z),
            target,
            inverted: false,
        };
        // A -O0 switch comparison ladder: two conditional blocks whose case
        // bodies reconverge at a distant join (b5), not an immediate diamond.
        // The post-dominator fallback must fold this into nested if/else instead
        // of leaving it Unstructured (goto soup).
        //   b0 -> b1(fall) / b3(taken)     b1 -> b2(fall) / b4(taken)
        //   b2,b3,b4 -> b5(join); b5 returns.
        let lf = mk_cfg(vec![
            (0x1000, vec![cj(0x1030)], vec![0x1010, 0x1030]), // 0
            (0x1010, vec![cj(0x1040)], vec![0x1020, 0x1040]), // 1
            (0x1020, vec![Op::Nop], vec![0x1050]),            // 2 default
            (0x1030, vec![Op::Nop], vec![0x1050]),            // 3 case
            (0x1040, vec![Op::Nop], vec![0x1050]),            // 4 case
            (0x1050, vec![Op::Return], vec![]),               // 5 join
        ]);
        let r = recover_for(&lf);
        let dbg = format!("{:?}", r);
        assert!(
            dbg.matches("IfThenElse").count() >= 2,
            "ladder should nest into >=2 if-else, got: {}",
            dbg
        );
        assert!(
            !dbg.contains("Unstructured"),
            "ladder must be fully structured, got: {}",
            dbg
        );
    }

    #[test]
    fn comparison_ladder_inside_loop_keeps_complex_fallthrough_arm_in_body() {
        use crate::ir::types::{Flag, VReg};

        let branch = |target: u64| Op::CondJump {
            cond: VReg::Flag(Flag::Z),
            target,
            inverted: false,
        };
        // GCC -O0 lowers a switch in a loop to a comparison ladder. At block 3
        // the taken edge goes straight to the latch while the fallthrough edge
        // continues through another conditional before reaching that latch:
        //
        //   entry -> header -> b2(case 3?) -> case3 -> latch -> header
        //                       |                ^
        //                       v                |
        //                      b3(skip rest?) --+
        //                       |
        //                      b4(case 2?) -> case2 -> latch
        //
        // The complex fallthrough arm is part of the natural loop. Leaving it
        // as a function-level leftover moves it after the return and drops the
        // corresponding switch cases.
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Jump { target: 0x1100 }], vec![0x1100]),
            (0x1100, vec![branch(0x1200)], vec![0x1200, 0x1800]), // header
            (0x1200, vec![branch(0x1700)], vec![0x1300, 0x1700]),
            (0x1300, vec![branch(0x1600)], vec![0x1400, 0x1600]),
            (0x1400, vec![branch(0x1500)], vec![0x1600, 0x1500]),
            (0x1500, vec![Op::Jump { target: 0x1600 }], vec![0x1600]),
            (0x1600, vec![Op::Jump { target: 0x1100 }], vec![0x1100]), // latch
            (0x1700, vec![Op::Jump { target: 0x1600 }], vec![0x1600]),
            (0x1800, vec![Op::Return], vec![]),
        ]);

        let region = recover_for(&lf);
        let rendered = format!("{region:#?}");
        assert!(
            !rendered.contains("Unstructured"),
            "loop ladder blocks escaped to a leftover region: {rendered}"
        );
        let Region::Seq(parts) = &region else {
            panic!("expected entry, loop, and exit: {region:#?}");
        };
        let Some(Region::While { body, .. }) = parts
            .iter()
            .find(|part| matches!(part, Region::While { .. }))
        else {
            panic!("expected recovered loop: {region:#?}");
        };
        let loop_blocks: HashSet<usize> = body.blocks().into_iter().collect();
        assert_eq!(
            loop_blocks,
            HashSet::from([2, 3, 4, 5, 6, 7]),
            "every comparison and case block must remain in the loop body"
        );
    }

    #[test]
    fn rotated_for_loop_is_recovered_as_while() {
        // gcc -O0 for-loop shape (from `sum_to`): entry jumps forward to the
        // condition block, which conditionally branches *back* to the body.
        //   B0(entry) -> COND
        //   COND -> BODY (taken, back-edge target) / AFTER (fallthrough)
        //   BODY -> COND
        // Block order in memory is B0, BODY, COND, AFTER.
        let lf = mk_cfg(vec![
            (0x10f9, vec![Op::Nop], vec![0x1122]),         // 0: B0  -> COND
            (0x1115, vec![Op::Nop], vec![0x1122]),         // 1: BODY-> COND
            (0x1122, vec![Op::Nop], vec![0x1115, 0x112a]), // 2: COND-> BODY/AFTER
            (0x112a, vec![Op::Return], vec![]),            // 3: AFTER
        ]);
        let r = recover_for(&lf);
        let has_while = format!("{:?}", r).contains("While");
        assert!(
            has_while,
            "rotated for-loop not structured as While: {:?}",
            r
        );
    }

    #[test]
    fn optional_preheader_with_early_return_joins_before_the_shared_loop() {
        use crate::ir::types::{Flag, VReg};

        let branch = |target: u64| {
            vec![Op::CondJump {
                cond: VReg::Flag(Flag::Z),
                target,
                inverted: false,
            }]
        };
        // GCC -O2 `sum_to` / `factorial` peel one iteration according to parity:
        //
        //          b0
        //       /      \
        //      b1       |       b1 is an optional one-time preheader
        //    /   \      |       whose side exit returns from the function
        //   b2   exit   |
        //     \         /
        //       loop_header -> loop_body -> loop_header
        //              \
        //               exit
        //
        // The function exit is b0's global post-dominator, but it is not the
        // conditional's local join. Nesting the loop in only b0's direct arm
        // makes the preheader path skip every remaining iteration.
        let lf = mk_cfg(vec![
            (0x1000, branch(0x1030), vec![0x1010, 0x1030]), // b0
            (0x1010, branch(0x1050), vec![0x1020, 0x1050]), // b1
            (0x1020, vec![Op::Nop], vec![0x1030]),          // b2
            (0x1030, branch(0x1050), vec![0x1040, 0x1050]), // loop header
            (0x1040, vec![Op::Jump { target: 0x1030 }], vec![0x1030]),
            (0x1050, vec![Op::Return], vec![]),
        ]);

        let region = recover_for(&lf);
        let Region::Seq(parts) = &region else {
            panic!("expected preheader, shared loop, and exit sequence: {region:#?}");
        };
        assert!(
            matches!(
                parts.first(),
                Some(Region::IfThen {
                    cond: 0,
                    join: Some(3),
                    ..
                })
            ),
            "the optional setup must join at the loop header: {region:#?}"
        );
        assert!(
            matches!(parts.get(1), Some(Region::While { header: 3, .. })),
            "the loop must be shared after the optional setup: {region:#?}"
        );
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
                        ..
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
                    Region::IfThen {
                        cond, then_r, join, ..
                    } => {
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
    fn bottom_tested_loop_recovers_as_do_while() {
        //   B0: entry
        //   B1: body
        //   B2: conditional latch -> B1 (continue), B3 (exit)
        //   B3: return
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100]),
            (0x1100, vec![Op::Nop], vec![0x1200]),
            (
                0x1200,
                vec![Op::CondJump {
                    cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                    target: 0x1100,
                    inverted: false,
                }],
                vec![0x1100, 0x1300],
            ),
            (0x1300, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        match r {
            Region::Seq(parts) => {
                assert_eq!(parts[0], Region::Block(0));
                match &parts[1] {
                    Region::DoWhile { body, cond, exit } => {
                        assert_eq!(**body, Region::Block(1));
                        assert_eq!(*cond, 2);
                        assert_eq!(*exit, Some(3));
                    }
                    other => panic!("expected DoWhile; got {other:?}"),
                }
                assert_eq!(parts[2], Region::Block(3));
            }
            other => panic!("expected Seq; got {other:?}"),
        }
    }

    #[test]
    fn single_block_bottom_tested_loop_recovers_as_do_while() {
        // The body and latch share one block, as emitted for compact do-while
        // loops after CFG block splitting.
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100]),
            (
                0x1100,
                vec![
                    Op::Nop,
                    Op::CondJump {
                        cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                        target: 0x1100,
                        inverted: false,
                    },
                ],
                vec![0x1100, 0x1200],
            ),
            (0x1200, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        match &r {
            Region::Seq(parts) => match &parts[1] {
                Region::DoWhile { body, cond, exit } => {
                    assert_eq!(**body, Region::Seq(Vec::new()));
                    assert_eq!(*cond, 1);
                    assert_eq!(*exit, Some(2));
                }
                other => panic!("expected DoWhile; got {other:?}"),
            },
            other => panic!("expected Seq; got {other:?}"),
        }
        let succs = vec![vec![1], vec![1, 2], vec![]];
        assert!(verify_region(&succs, 0, &r).is_empty());
    }

    #[test]
    fn multiple_back_edges_do_not_turn_a_pretested_loop_into_do_while() {
        // B1 is the pre-test. B2 can continue directly to it, while B3 is the
        // ordinary latch. Treating B2 as a bottom-test would skip B1 before the
        // first iteration and was enough to break five -O2 fixture canaries.
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100]),
            (
                0x1100,
                vec![Op::CondJump {
                    cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                    target: 0x1400,
                    inverted: false,
                }],
                vec![0x1200, 0x1400],
            ),
            (
                0x1200,
                vec![Op::CondJump {
                    cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::S),
                    target: 0x1100,
                    inverted: false,
                }],
                vec![0x1100, 0x1300],
            ),
            (0x1300, vec![Op::Jump { target: 0x1100 }], vec![0x1100]),
            (0x1400, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        fn contains_do_while(region: &Region) -> bool {
            match region {
                Region::DoWhile { .. } => true,
                Region::Seq(parts) => parts.iter().any(contains_do_while),
                Region::IfThen { then_r, .. } => contains_do_while(then_r),
                Region::IfThenElse { then_r, else_r, .. } => {
                    contains_do_while(then_r) || contains_do_while(else_r)
                }
                Region::While { body, .. } => contains_do_while(body),
                Region::MultiExitLoop { body, .. } => contains_do_while(body),
                Region::Switch { arms, .. } => arms.iter().any(contains_do_while),
                Region::Block(_)
                | Region::Goto(_)
                | Region::RawLoop { .. }
                | Region::Unstructured(_) => false,
            }
        }
        assert!(
            !contains_do_while(&r),
            "pre-tested loop became DoWhile: {r:#?}"
        );
    }

    #[test]
    fn multi_latch_loop_with_distinct_early_and_normal_exits_falls_back_totally() {
        // Optimised binary-search shape (clang -O2): B3 is the rotated loop
        // header, B2 and B5 are distinct latches, B7 is the successful early
        // return, and B6 is the ordinary exhausted-range return.
        //
        // Region::While has one header exit.  Choosing B7 strands both latch
        // arms after the successful return; choosing B6 invents a header edge
        // which does not exist.  Until the region algebra represents multiple
        // owned exits, the semantics-preserving representation is the complete
        // labelled CFG, not a lossy While plus leftovers.
        let cond = |target| {
            vec![Op::CondJump {
                cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                target,
                inverted: false,
            }]
        };
        let lf = mk_cfg(vec![
            (0x1000, cond(0x1600), vec![0x1100, 0x1600]), // initial empty test
            (0x1100, vec![Op::Nop], vec![0x1300]),        // initialise bounds
            (0x1200, cond(0x1600), vec![0x1300, 0x1600]), // high-side latch
            (0x1300, cond(0x1700), vec![0x1400, 0x1700]), // compare / found
            (0x1400, cond(0x1200), vec![0x1200, 0x1500]), // choose update arm
            (0x1500, cond(0x1300), vec![0x1300, 0x1600]), // low-side latch
            (0x1600, vec![Op::Return], vec![]),           // not found
            (0x1700, vec![Op::Return], vec![]),           // found
        ]);

        let ssa = compute_ssa(&lf);
        let (r, health) = recover_verified_with_health(&lf, &ssa);
        assert_eq!(r, Region::Unstructured((0..8).collect()), "{r:#?}");
        assert_eq!(health.structure_fallbacks, 1);
        assert_eq!(health.uncovered_cfg_edges, 0);
        assert_eq!(health.invented_cfg_edges, 0);
        assert!(verify_structure(&lf, &ssa).is_empty());
    }

    #[test]
    fn single_latch_unrolled_search_with_distinct_early_returns_stays_structured() {
        // Reduced Clang -O2 `find_first_set`: B1 is the loop header, B5 is its
        // sole latch, and B1..B4 each have a different terminal success exit.
        // The bounded While builder currently structures only the first two
        // tests, then strands B4/B5 after a return and invents edges around B3.
        // Terminal arms stay as returns inside the loop, while the ordinary
        // exhaustion bridge becomes an owned loop exit.
        let cond = |target| {
            vec![Op::CondJump {
                cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::C),
                target,
                inverted: false,
            }]
        };
        let lf = mk_cfg(vec![
            (0x1230, vec![Op::Nop], vec![0x1240]),
            (0x1240, cond(0x127b), vec![0x127b, 0x1245]),
            (0x1245, cond(0x1274), vec![0x1274, 0x1250]),
            (0x1250, cond(0x1278), vec![0x1278, 0x125b]),
            (0x125b, cond(0x127c), vec![0x127c, 0x1266]),
            (0x1266, cond(0x1240), vec![0x1240, 0x126e]),
            (0x126e, vec![Op::Return], vec![]),
            (0x1274, vec![Op::Return], vec![]),
            (0x1278, vec![Op::Nop], vec![0x127b]),
            (0x127b, vec![Op::Return], vec![]),
            (0x127c, vec![Op::Return], vec![]),
        ]);

        let region = recover_for(&lf);
        let errors = verify_structure(&lf, &compute_ssa(&lf));
        let rendered = format!("{region:#?}");
        assert!(rendered.contains("While"), "loop was lost: {rendered}");
        assert!(
            !rendered.contains("Unstructured"),
            "early-return arms escaped the loop: {rendered}"
        );
        assert!(errors.is_empty());
    }

    #[test]
    fn multi_latch_loop_with_one_shared_exit_has_an_owned_raw_loop() {
        let cond = |target| {
            vec![Op::CondJump {
                cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                target,
                inverted: false,
            }]
        };
        // Reduced GCC -O2 switch-in-loop shape. The header is an internal
        // dispatch, not the loop test: both successors remain in the body.
        // Each arm has its own conditional latch, and both latches either
        // re-enter the header or leave through the same exit.
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Jump { target: 0x1100 }], vec![0x1100]),
            (0x1100, cond(0x1200), vec![0x1200, 0x1300]), // internal dispatch
            (0x1200, cond(0x1100), vec![0x1100, 0x1400]), // latch 1
            (0x1300, cond(0x1100), vec![0x1100, 0x1400]), // latch 2
            (0x1400, vec![Op::Return], vec![]),
        ]);

        let region = recover_for(&lf);
        let rendered = format!("{region:#?}");
        assert!(
            rendered.contains("RawLoop"),
            "the two latches need one owned loop region: {rendered}"
        );
        assert!(
            !rendered.contains("Unstructured"),
            "loop blocks must not escape to function-level leftovers: {rendered}"
        );
        assert!(verify_structure(&lf, &compute_ssa(&lf)).is_empty());
    }

    #[test]
    fn nested_loop_with_distinct_match_and_exhaustion_exits_falls_back_totally() {
        // Reduced GCC -O2 `has_pair`. B4/B3 is the inner search loop: B4's
        // match edge returns through B5, while B3's exhausted edge reaches the
        // outer latch B6 and eventually re-enters through B2. A Region::While
        // has only one distinguished exit. Treating B5 as that exit absorbed
        // B6 into the loop body but dropped B2's reload/reset, causing an
        // out-of-bounds search and false positive return on a real 16-element
        // differential vector.
        let cond = |target| {
            vec![Op::CondJump {
                cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                target,
                inverted: false,
            }]
        };
        let lf = mk_cfg(vec![
            (0x1000, cond(0x1700), vec![0x1100, 0x1700]), // empty input guard
            (0x1100, cond(0x1700), vec![0x1200, 0x1700]), // one-element guard
            (0x1200, vec![Op::Nop], vec![0x1400]),        // load a[i], reset j
            (0x1300, cond(0x1600), vec![0x1400, 0x1600]), // inner latch/exhausted
            (0x1400, cond(0x1500), vec![0x1300, 0x1500]), // compare/match
            (0x1500, vec![Op::Return], vec![]),           // found
            (0x1600, cond(0x1200), vec![0x1200, 0x1700]), // outer latch/back-edge
            (0x1700, vec![Op::Return], vec![]),           // not found
        ]);

        let r = recover_for(&lf);
        assert_eq!(r, Region::Unstructured((0..8).collect()), "{r:#?}");
        assert!(verify_structure(&lf, &compute_ssa(&lf)).is_empty());
    }

    #[test]
    fn nonterminal_inner_exit_does_not_force_a_whole_function_fallback() {
        // Both exits from the inner cycle continue into outer-loop work. This
        // is the ordinary nested-loop class used by matrix/sort code, not the
        // `has_pair` class where the header exit returns from the function.
        let cond = |target| {
            vec![Op::CondJump {
                cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                target,
                inverted: false,
            }]
        };
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1200]),
            (0x1100, vec![Op::Nop], vec![0x1200]),
            (0x1200, cond(0x1400), vec![0x1300, 0x1400]), // inner header / normal exit
            (0x1300, cond(0x1600), vec![0x1200, 0x1600]), // back-edge / secondary exit
            (0x1400, vec![Op::Nop], vec![0x1600]),        // post-inner continuation
            (0x1500, vec![Op::Nop], vec![0x1600]),
            (0x1600, cond(0x1200), vec![0x1200, 0x1700]), // outer latch / re-entry
            (0x1700, vec![Op::Return], vec![]),
        ]);
        let ssa = compute_ssa(&lf);
        let cfg = Cfg::from(&lf, &ssa);

        assert!(!has_inner_loop_exit_that_reenters_via_outer_cycle(&cfg));
    }

    #[test]
    fn loop_early_return_bridge_keeps_result_setup_inside_the_loop() {
        // GCC -O0 `fsm`: the loop header B1 normally exits through epilogue B6,
        // while B2 may return early through B5 -> B6 and its sibling continues
        // through the state-update ladder and latch.  B6 post-dominates B2 but
        // lies outside the loop.  Treating it as B2's local if/else join moves
        // the epilogue into the loop and strands the update ladder afterward.
        let cond = |target| {
            vec![Op::CondJump {
                cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                target,
                inverted: false,
            }]
        };
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100]),
            (0x1100, cond(0x1600), vec![0x1200, 0x1600]), // loop header / normal exit
            (0x1200, cond(0x1500), vec![0x1300, 0x1500]), // continue / early return
            (0x1300, vec![Op::Nop], vec![0x1400]),        // state update
            (0x1400, vec![Op::Jump { target: 0x1100 }], vec![0x1100]),
            (0x1500, vec![Op::Jump { target: 0x1600 }], vec![0x1600]),
            (0x1600, vec![Op::Return], vec![]),
        ]);

        let ssa = compute_ssa(&lf);
        let cfg = Cfg::from(&lf, &ssa);
        let candidate = build_full(&lf, &cfg);
        let accounting =
            crate::ir::structure_accounting::account(&cfg.edges, &cfg.preds, 0, &candidate);
        assert!(
            !accounting.iter().any(|error| matches!(
                error,
                crate::ir::structure_accounting::AccountError::BlockDropped { .. }
                    | crate::ir::structure_accounting::AccountError::EdgeUnaccounted { .. }
                    | crate::ir::structure_accounting::AccountError::BackEdgeUnowned { .. }
                    | crate::ir::structure_accounting::AccountError::ImpliedEdgeAbsent { .. }
                    | crate::ir::structure_accounting::AccountError::GotoTargetMissing { .. }
                    | crate::ir::structure_accounting::AccountError::SwitchArmOutsideLoop { .. }
            )),
            "candidate failed structural accounting: {candidate:#?}\n{accounting:#?}"
        );

        let r = recover_verified(&lf, &ssa);
        let rendered = format!("{r:#?}");
        assert!(rendered.contains("While"), "loop was lost: {rendered}");
        assert!(
            !rendered.contains("Unstructured"),
            "the result-setup bridge escaped the loop: {rendered}"
        );
        assert!(verify_structure(&lf, &compute_ssa(&lf)).is_empty());
    }

    #[test]
    fn branching_cleanup_after_loop_early_exit_forces_lossless_fallback() {
        // Clang -O0 `process`: an internal retry-loop condition can leave for
        // a BRANCHING cleanup ladder whose terminal return is also reached by
        // the loop's ordinary success path.  Pulling that shared return into
        // the loop body makes the success-path jump disappear during AST
        // lowering.  This is not the representable direct/linear `break`
        // bridge handled below, so retain the complete labelled CFG.
        let cond = |target| {
            vec![Op::CondJump {
                cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                target,
                inverted: false,
            }]
        };
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100]),
            (0x1100, cond(0x1500), vec![0x1200, 0x1500]), // retry header / success
            (0x1200, cond(0x1600), vec![0x1300, 0x1600]), // continue / cleanup
            (0x1300, vec![Op::Nop], vec![0x1400]),
            (0x1400, vec![Op::Jump { target: 0x1100 }], vec![0x1100]),
            (0x1500, vec![Op::Nop], vec![0x1900]), // success setup
            (0x1600, cond(0x1800), vec![0x1700, 0x1800]), // cleanup ladder
            (0x1700, vec![Op::Nop], vec![0x1900]),
            (0x1800, vec![Op::Nop], vec![0x1900]),
            (0x1900, vec![Op::Return], vec![]), // shared epilogue
        ]);
        let ssa = compute_ssa(&lf);
        let cfg = Cfg::from(&lf, &ssa);

        assert!(has_loop_conditional_with_join_beyond_loop(&cfg));
        assert_eq!(
            recover_verified(&lf, &ssa),
            Region::Unstructured((0..10).collect())
        );
    }

    #[test]
    fn direct_break_to_the_natural_loop_exit_keeps_the_rest_of_the_body() {
        // GCC -O0 Dijkstra shape: the loop header has the ordinary exhaustion
        // exit, and a body guard jumps DIRECTLY to that same exit (`break`).
        // The sibling continues through more body work and the one latch.  This
        // is representable without assigning the epilogue to the conditional:
        // `if (done) goto exit; work; latch;` inside the recovered While.
        let cond = |target| {
            vec![Op::CondJump {
                cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                target,
                inverted: false,
            }]
        };
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100]),
            (0x1100, cond(0x1500), vec![0x1200, 0x1500]), // header / exhausted
            (0x1200, cond(0x1500), vec![0x1300, 0x1500]), // work / direct break
            (0x1300, vec![Op::Nop], vec![0x1400]),        // remaining body work
            (0x1400, vec![Op::Jump { target: 0x1100 }], vec![0x1100]),
            (0x1500, vec![Op::Return], vec![]),
        ]);

        let region = recover_verified(&lf, &compute_ssa(&lf));
        let rendered = format!("{region:#?}");
        assert!(rendered.contains("While"), "loop was lost: {rendered}");
        assert!(
            rendered.contains("Goto(\n"),
            "break edge was lost: {rendered}"
        );
        assert!(
            !rendered.contains("Unstructured"),
            "remaining body blocks escaped the loop: {rendered}"
        );
    }

    #[test]
    fn a_structured_top_guard_can_own_the_zero_iteration_case_of_a_rotated_loop() {
        // B0 can bypass the body before its first iteration, while B2 is the
        // bottom latch for subsequent iterations. Once B0 has been retained as
        // an explicit terminal guard, the continuation is exactly a do-while:
        //
        //     if (empty) return;
        //     do { body; } while (more);
        //
        // Rejecting the latch after proving that guard strands the natural
        // cycle and forces an otherwise reducible function to labelled CFG.
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![Op::CondJump {
                    cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                    target: 0x1300,
                    inverted: false,
                }],
                vec![0x1100, 0x1300],
            ),
            (0x1100, vec![Op::Nop], vec![0x1200]),
            (
                0x1200,
                vec![Op::CondJump {
                    cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::S),
                    target: 0x1100,
                    inverted: false,
                }],
                vec![0x1100, 0x1300],
            ),
            (0x1300, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        let ssa = compute_ssa(&lf);
        let cfg = Cfg::from(&lf, &ssa);
        let accounting = crate::ir::structure_accounting::account(&cfg.edges, &cfg.preds, 0, &r);
        let rendered = format!("{r:#?}");
        assert!(
            rendered.contains("DoWhile"),
            "the guarded rotated loop was not owned: {rendered}"
        );
        assert!(
            !rendered.contains("Unstructured"),
            "the guarded rotated loop escaped to leftovers: {rendered}"
        );
        assert!(
            accounting.iter().all(|error| !matches!(
                error,
                crate::ir::structure_accounting::AccountError::BlockDropped { .. }
                    | crate::ir::structure_accounting::AccountError::EdgeUnaccounted { .. }
                    | crate::ir::structure_accounting::AccountError::BackEdgeUnowned { .. }
                    | crate::ir::structure_accounting::AccountError::ImpliedEdgeAbsent { .. }
                    | crate::ir::structure_accounting::AccountError::GotoTargetMissing { .. }
                    | crate::ir::structure_accounting::AccountError::SwitchArmOutsideLoop { .. }
            )),
            "the guarded rotated loop must account for every edge: {accounting:#?}\n{rendered}"
        );
    }

    #[test]
    fn an_if_arm_can_be_a_loop_whose_only_exit_is_the_join() {
        // Clang's bounded inner loops often use a direct skip edge from the
        // surrounding condition and place the real test in a bottom latch:
        //
        //        B0
        //      /    \
        //    B1      B5(join)
        //     |       ^
        //    B2 -> B4 |
        //     ^    |  |
        //     |    v  |
        //     +--- B3-+
        //
        // The arm is cyclic, so the acyclic `every_path_reaches_join` proof
        // declines it even though every loop block can reach the sole join.
        let conditional = |target| {
            vec![Op::CondJump {
                cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                target,
                inverted: false,
            }]
        };
        let lf = mk_cfg(vec![
            (0x1000, conditional(0x1700), vec![0x1100, 0x1700]), // initial outer guard
            (0x1100, conditional(0x1600), vec![0x1200, 0x1600]), // skip inner loop
            (0x1200, vec![Op::Jump { target: 0x1300 }], vec![0x1300]),
            (0x1300, conditional(0x1400), vec![0x1400, 0x1500]), // inner body
            (0x1400, conditional(0x1300), vec![0x1300, 0x1600]), // inner latch
            (0x1500, vec![Op::Jump { target: 0x1400 }], vec![0x1400]),
            (0x1600, conditional(0x1100), vec![0x1100, 0x1700]), // outer latch
            (0x1700, vec![Op::Return], vec![]),
        ]);

        let ssa = compute_ssa(&lf);
        let cfg = Cfg::from(&lf, &ssa);
        let region = recover(&lf, &ssa);
        let rendered = format!("{region:#?}");
        let accounting =
            crate::ir::structure_accounting::account(&cfg.edges, &cfg.preds, 0, &region);
        assert!(
            rendered.contains("DoWhile"),
            "inner loop was lost: {rendered}"
        );
        assert!(
            !rendered.contains("Unstructured"),
            "cyclic if arm escaped to leftovers: {rendered}"
        );
        assert!(
            accounting.iter().all(|error| !matches!(
                error,
                crate::ir::structure_accounting::AccountError::BlockDropped { .. }
                    | crate::ir::structure_accounting::AccountError::EdgeUnaccounted { .. }
                    | crate::ir::structure_accounting::AccountError::BackEdgeUnowned { .. }
                    | crate::ir::structure_accounting::AccountError::ImpliedEdgeAbsent { .. }
                    | crate::ir::structure_accounting::AccountError::GotoTargetMissing { .. }
                    | crate::ir::structure_accounting::AccountError::SwitchArmOutsideLoop { .. }
            )),
            "{accounting:#?}\n{rendered}"
        );
    }

    #[test]
    fn a_shared_fallthrough_owned_by_the_later_sibling_keeps_its_edge() {
        // Clang 21 emits this inside topological-sort's queue seed loop. B1's
        // taken edge reaches the join, while its fallthrough reaches B4, which
        // is also the tail of the sibling arm. The sibling is built later, so
        // B4 is not visited yet when B1 declines high-level if recovery:
        //
        //             B0
        //           /    \
        //         B1      B2
        //        /  \\      |
        //    join   B4 <- B3
        //             \\   /
        //              join
        //
        // Dropping B1 -> B4 makes accounting reject all otherwise recovered
        // loops and falls back to whole-function labelled CFG.
        let conditional = |target| {
            vec![Op::CondJump {
                cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                target,
                inverted: false,
            }]
        };
        let lf = mk_cfg(vec![
            (0x1000, conditional(0x1300), vec![0x1200, 0x1300]),
            (0x1100, vec![Op::Jump { target: 0x1200 }], vec![0x1200]),
            (0x1200, vec![Op::Jump { target: 0x1300 }], vec![0x1300]),
            (0x1300, conditional(0x1400), vec![0x1400, 0x1500]),
            (0x1400, vec![Op::Return], vec![]),
            (0x1500, vec![Op::Jump { target: 0x1300 }], vec![0x1300]),
        ]);

        let ssa = compute_ssa(&lf);
        let cfg = Cfg::from(&lf, &ssa);
        let region = build(0, &cfg, &mut HashSet::new(), Some(3));

        assert!(
            format!("{region:#?}").contains("Goto(\n            2"),
            "the displaced fallthrough needs an explicit edge: {region:#?}"
        );
    }

    #[test]
    fn a_cloned_shared_epilogue_does_not_erase_an_accounted_loop() {
        // Both the initial zero-iteration guard and the bottom latch leave
        // through B3 -> B4. Shared-return recovery deliberately clones B4 in
        // the guard but retains one canonical B4 as a leftover label. That is
        // a quality diagnostic (BlockDuplicated), not a reason to replace the
        // fully accounted loop with whole-function Unstructured fallback.
        let conditional = |target| {
            vec![Op::CondJump {
                cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                target,
                inverted: false,
            }]
        };
        let lf = mk_cfg(vec![
            (0x1000, conditional(0x1400), vec![0x1100, 0x1400]), // direct shared epilogue
            (0x1100, conditional(0x1300), vec![0x1200, 0x1300]), // initial loop guard
            (0x1200, conditional(0x1200), vec![0x1200, 0x1300]), // bottom latch
            (0x1300, vec![Op::Jump { target: 0x1400 }], vec![0x1400]),
            (0x1400, vec![Op::Return], vec![]),
        ]);

        let ssa = compute_ssa(&lf);
        let cfg = Cfg::from(&lf, &ssa);
        let region = recover(&lf, &ssa);
        let accounting =
            crate::ir::structure_accounting::account(&cfg.edges, &cfg.preds, 0, &region);
        let rendered = format!("{region:#?}");
        assert!(
            rendered.contains("DoWhile"),
            "accounted loop was erased: {rendered}"
        );
        assert!(
            accounting.iter().any(|error| matches!(
                error,
                crate::ir::structure_accounting::AccountError::BlockDuplicated { block: 4, .. }
            )),
            "the fixture must exercise deliberate epilogue cloning: {accounting:#?}"
        );
        assert!(
            !structure_accounting_is_unsound(&accounting),
            "the cloned epilogue must not hide a real edge defect: {accounting:#?}"
        );
    }

    #[test]
    fn a_nested_conditional_latch_exit_is_not_silently_dropped() {
        // Reduced only at the instruction level from the real GCC 15 -O2 CFG
        // for recursive Fibonacci. GCC expands most recursion into nested
        // loops, with one cold bridge (B31) re-entering B23. The speculative
        // region tree duplicated the epilogue and left a nested back-edge
        // unowned. AST lowering then erased six conditional latches as empty
        // `if`s; fib(20) never terminated.
        let cj = |target| {
            vec![Op::CondJump {
                cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                target,
                inverted: false,
            }]
        };
        let j = |target| vec![Op::Jump { target }];
        let lf = mk_cfg(vec![
            (0x1100, cj(0x13cf), vec![0x13cf, 0x111e]),
            (0x111e, j(0x1132), vec![0x1132]),
            (0x1132, cj(0x13c8), vec![0x13c8, 0x113b]),
            (0x113b, j(0x115e), vec![0x115e]),
            (0x115e, cj(0x13b0), vec![0x13b0, 0x1168]),
            (0x1168, j(0x1188), vec![0x1188]),
            (0x1188, cj(0x1393), vec![0x1393, 0x1192]),
            (0x1192, j(0x11b6), vec![0x11b6]),
            (0x11b6, cj(0x1373), vec![0x1373, 0x11c0]),
            (0x11c0, j(0x11ea), vec![0x11ea]),
            (0x11ea, cj(0x134f), vec![0x134f, 0x11f3]),
            (0x11f3, j(0x1209), vec![0x1209]),
            (0x1209, cj(0x133f), vec![0x133f, 0x1213]),
            (0x1213, cj(0x1322), vec![0x1322, 0x124b]),
            (0x124b, j(0x1265), vec![0x1265]),
            (0x1265, cj(0x12f0), vec![0x12f0, 0x1270]),
            (0x1270, j(0x1272), vec![0x1272]),
            (0x1272, cj(0x1272), vec![0x1272, 0x12c5]),
            (0x12c5, cj(0x1265), vec![0x1265, 0x12e5]),
            (0x12e5, j(0x12f0), vec![0x12f0]),
            (0x12f0, cj(0x13e1), vec![0x13e1, 0x1316]),
            (0x1316, cj(0x124b), vec![0x124b, 0x1322]),
            (0x1322, j(0x132f), vec![0x132f]),
            (0x132f, cj(0x1209), vec![0x1209, 0x133f]),
            (0x133f, cj(0x11ea), vec![0x11ea, 0x134f]),
            (0x134f, cj(0x11b6), vec![0x11b6, 0x1373]),
            (0x1373, cj(0x1188), vec![0x1188, 0x1393]),
            (0x1393, cj(0x115e), vec![0x115e, 0x13b0]),
            (0x13b0, cj(0x1132), vec![0x1132, 0x13c8]),
            (0x13c8, j(0x13cf), vec![0x13cf]),
            (0x13cf, vec![Op::Return], vec![]),
            (0x13e1, j(0x132f), vec![0x132f]),
        ]);

        let ssa = compute_ssa(&lf);
        let cfg = Cfg::from(&lf, &ssa);
        let speculative = build_full(&lf, &cfg);
        let accounting =
            crate::ir::structure_accounting::account(&cfg.edges, &cfg.preds, 0, &speculative);
        assert!(
            accounting.iter().any(|error| matches!(
                error,
                crate::ir::structure_accounting::AccountError::BlockDuplicated { .. }
                    | crate::ir::structure_accounting::AccountError::BackEdgeUnowned { .. }
                    | crate::ir::structure_accounting::AccountError::ImpliedEdgeAbsent { .. }
            )),
            "the reduced real CFG must retain a soundness finding: {accounting:?}"
        );

        let region = recover_verified(&lf, &ssa);
        assert_eq!(
            region,
            Region::Unstructured((0..32).collect()),
            "an unfaithful nested loop must retain its complete labelled CFG: {region:#?}"
        );
    }

    #[test]
    fn a_guarded_rotated_division_loop_owns_its_backedge() {
        // Reduced from the real Clang 21 -O2 `fixedpoint:isqrt` CFG. The
        // compiler splits signed division into fast and slow paths (B2/B5),
        // joins them at B3, and then either exits or re-enters through B4:
        //
        //   B0 -> B1 (return n) | B4
        //   B4 -> B2 (signed divide) | B5 (unsigned fast path)
        //   B2/B5 -> B3
        //   B3 -> B4 (back edge) | B6 (return x)
        //
        // This was the original unowned-backedge canary: lowering emitted one
        // iteration and isqrt(100) returned 50 instead of 10. Once B0's
        // zero-iteration return is retained as a guard, B4..B3 are an exact
        // bottom-tested loop and both division arms belong inside it.
        let cond = |target| {
            vec![Op::CondJump {
                cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                target,
                inverted: false,
            }]
        };
        let lf = mk_cfg(vec![
            (0x1140, cond(0x117d), vec![0x1157, 0x117d]),
            (0x1157, vec![Op::Return], vec![]),
            (0x1160, vec![Op::Nop], vec![0x1168]),
            (0x1168, cond(0x1194), vec![0x117d, 0x1194]),
            (0x117d, cond(0x1160), vec![0x1160, 0x118c]),
            (0x118c, vec![Op::Jump { target: 0x1168 }], vec![0x1168]),
            (0x1194, vec![Op::Return], vec![]),
        ]);
        let ssa = compute_ssa(&lf);
        let cfg = Cfg::from(&lf, &ssa);
        let speculative = build_full(&lf, &cfg);
        let accounting =
            crate::ir::structure_accounting::account(&cfg.edges, &cfg.preds, 0, &speculative);
        assert!(accounting.is_empty(), "{accounting:#?}\n{speculative:#?}");
        assert!(
            format!("{speculative:#?}").contains("DoWhile"),
            "the guarded rotated cycle was not recovered: {speculative:#?}"
        );

        let region = recover_verified(&lf, &ssa);
        assert!(
            !format!("{region:#?}").contains("Unstructured"),
            "a fully accounted loop must survive verification: {region:#?}"
        );
    }

    #[test]
    fn early_exit_loop_is_not_promoted_to_plain_do_while() {
        // Entry into B1 is unconditional, but B1 can return through B3 before
        // reaching the latch B2. A DoWhile with only `{body, cond, exit}` cannot
        // own that second exit without moving it to the wrong nesting level.
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100]),
            (
                0x1100,
                vec![Op::CondJump {
                    cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                    target: 0x1300,
                    inverted: false,
                }],
                vec![0x1200, 0x1300],
            ),
            (
                0x1200,
                vec![Op::CondJump {
                    cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::S),
                    target: 0x1100,
                    inverted: false,
                }],
                vec![0x1100, 0x1400],
            ),
            (0x1300, vec![Op::Return], vec![]),
            (0x1400, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        fn contains_do_while(region: &Region) -> bool {
            match region {
                Region::DoWhile { .. } => true,
                Region::Seq(parts) => parts.iter().any(contains_do_while),
                Region::IfThen { then_r, .. } => contains_do_while(then_r),
                Region::IfThenElse { then_r, else_r, .. } => {
                    contains_do_while(then_r) || contains_do_while(else_r)
                }
                Region::While { body, .. } => contains_do_while(body),
                Region::MultiExitLoop { body, .. } => contains_do_while(body),
                Region::Switch { arms, .. } => arms.iter().any(contains_do_while),
                Region::Block(_)
                | Region::Goto(_)
                | Region::RawLoop { .. }
                | Region::Unstructured(_) => false,
            }
        }
        assert!(
            !contains_do_while(&r),
            "early-exit loop became DoWhile: {r:#?}"
        );
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
                    Region::IfThen {
                        cond, then_r, join, ..
                    } => {
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
    fn nonreturning_terminal_guard_is_body_independent_of_successor_order() {
        use crate::ir::types::{CallTarget, Flag, VReg};

        // The branch target is the successful continuation and the lexical
        // fallthrough is a non-returning guard body. Deliberately list the
        // taken target first: successor-vector order is not branch semantics.
        //
        //   b0: if (ok) goto b2
        //   b1: exit / unreachable       (fallthrough)
        //   b2: normal work; return      (taken target)
        //
        // Both arms terminate at CFG level, but presentation must remain
        // Seq[if (!ok) b1, b2], matching the machine fallthrough topology.
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![Op::CondJump {
                    cond: VReg::Flag(Flag::Z),
                    target: 0x1200,
                    inverted: false,
                }],
                vec![0x1200, 0x1100],
            ),
            (
                0x1100,
                vec![Op::Call {
                    target: CallTarget::Direct(0x9000),
                    effects: None,
                }],
                vec![],
            ),
            (0x1200, vec![Op::Return], vec![]),
        ]);

        let r = recover_for(&lf);
        let Region::Seq(parts) = r else {
            panic!("expected terminal guard followed by continuation; got {r:?}");
        };
        assert_eq!(parts.len(), 2, "unexpected region sequence: {parts:?}");
        match &parts[0] {
            Region::IfThen {
                cond,
                then_r,
                join,
                invert,
            } => {
                assert_eq!(*cond, 0);
                assert_eq!(**then_r, Region::Block(1));
                assert_eq!(*join, None);
                assert!(*invert, "the raw taken condition must be negated");
            }
            other => panic!("expected one-arm terminal guard; got {other:?}"),
        }
        assert_eq!(parts[1], Region::Block(2));
    }

    #[test]
    fn two_returning_terminals_prefer_the_taken_edge_as_the_if_body() {
        use crate::ir::types::{Flag, VReg};

        // With two ordinary return arms there is no unique non-returning guard.
        // Resolve the tie from the conditional's semantic taken edge, never
        // from whichever successor happens to occupy a vector slot.
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![Op::CondJump {
                    cond: VReg::Flag(Flag::Z),
                    target: 0x1200,
                    inverted: false,
                }],
                vec![0x1200, 0x1100],
            ),
            (0x1100, vec![Op::Return], vec![]),
            (0x1200, vec![Op::Return], vec![]),
        ]);

        let r = recover_for(&lf);
        let Region::Seq(parts) = r else {
            panic!("expected terminal branch followed by sibling; got {r:?}");
        };
        assert_eq!(parts.len(), 2, "unexpected region sequence: {parts:?}");
        match &parts[0] {
            Region::IfThen { then_r, invert, .. } => {
                assert_eq!(**then_r, Region::Block(2));
                assert!(!*invert, "the taken arm uses the raw condition");
            }
            other => panic!("expected one-arm terminal branch; got {other:?}"),
        }
        assert_eq!(parts[1], Region::Block(1));
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
            "expected structured shape; got {:?}",
            r,
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
                        count += c;
                        bad |= b;
                    }
                    (count, bad)
                }
                Region::IfThen { then_r, .. } => count_block(then_r, target),
                Region::IfThenElse { then_r, else_r, .. } => {
                    let (c1, b1) = count_block(then_r, target);
                    let (c2, b2) = count_block(else_r, target);
                    (c1 + c2, b1 || b2)
                }
                Region::While { body, .. }
                | Region::DoWhile { body, .. }
                | Region::MultiExitLoop { body, .. } => count_block(body, target),
                Region::RawLoop { blocks, .. } => (
                    blocks.iter().filter(|&&block| block == target).count(),
                    false,
                ),
                Region::Switch { arms, .. } => {
                    let mut count = 0;
                    let mut bad = false;
                    for a in arms {
                        let (c, b) = count_block(a, target);
                        count += c;
                        bad |= b;
                    }
                    (count, bad)
                }
                Region::Goto(_) => (0, false),
                Region::Unstructured(_) => (0, true),
            }
        }
        let (count, has_unstructured) = count_block(&r, 3);
        assert!(!has_unstructured, "expected no Unstructured; got {:?}", r);
        assert!(
            count >= 2,
            "expected shared-exit block referenced >=2 times; got {} in {:?}",
            count,
            r
        );
    }

    #[test]
    fn split_shared_return_epilogue_is_cloned_into_loop_exit_guards() {
        use crate::ir::types::{Flag, VReg};

        let branch = |target| {
            vec![Op::CondJump {
                cond: VReg::Flag(Flag::Z),
                target,
                inverted: false,
            }]
        };
        // Clang -O2 `list_find`:
        //
        //   entry --null----------------------> zero_result -> return
        //     |                                     ^           ^
        //     v                                     |           |
        //   loop_header --match---------------------------------+
        //     |                                     |
        //   advance --null--------------------------+
        //     |
        //     +-------------------------> loop_header
        //
        // `zero_result` and `return` are separate blocks.  Both null edges are
        // source-level early returns and must not become gotos into another
        // structured arm merely because the value setup precedes the terminal.
        let lf = mk_cfg(vec![
            (0x1120, branch(0x113d), vec![0x1125, 0x113d]),
            (0x1125, vec![Op::Nop], vec![0x1130]),
            (0x1130, branch(0x113f), vec![0x1135, 0x113f]),
            (0x1135, branch(0x1130), vec![0x1130, 0x113d]),
            (0x113d, vec![Op::Nop], vec![0x113f]),
            (0x113f, vec![Op::Return], vec![]),
        ]);

        let region = recover_for(&lf);
        let rendered = format!("{region:?}");
        assert!(
            !rendered.contains("Goto(4)"),
            "the null-result chain must be cloned as an early return: {region:#?}"
        );
        assert!(
            region.blocks().iter().filter(|&&block| block == 4).count() >= 2,
            "both null guards must own the shared result setup: {region:#?}"
        );
        assert!(verify_structure(&lf, &compute_ssa(&lf)).is_empty());
    }

    #[test]
    fn cloned_return_prefix_remains_available_to_a_loop_exit() {
        use crate::ir::types::{Flag, VReg};

        let branch = |target| {
            vec![Op::CondJump {
                cond: VReg::Flag(Flag::Z),
                target,
                inverted: false,
            }]
        };
        // Reduced Clang `fib`: the entry base case and the loop's normal exit
        // both need b3 before the common return.  Cloning b3->b4 into the base
        // case must not mark b3 globally consumed or the loop result vanishes.
        let lf = mk_cfg(vec![
            (0x1000, branch(0x1300), vec![0x1100, 0x1300]),
            (0x1100, branch(0x1300), vec![0x1200, 0x1300]),
            (0x1200, vec![Op::Jump { target: 0x1100 }], vec![0x1100]),
            (0x1300, vec![Op::Nop], vec![0x1400]),
            (0x1400, vec![Op::Return], vec![]),
        ]);

        let region = recover_for(&lf);
        assert!(
            region.blocks().iter().filter(|&&block| block == 3).count() >= 2,
            "the shared result prefix must serve both entry and loop exits: {region:#?}"
        );
        assert!(verify_structure(&lf, &compute_ssa(&lf)).is_empty());

        // The same ownership rule applies when loop rotation places the
        // distinguished exit on a bottom latch rather than the header. This is
        // the Clang O2 topological-sort shape: consuming B3 into the entry
        // guard removes the post-loop result calculation from the normal path.
        let bottom_tested = mk_cfg(vec![
            (0x2000, branch(0x2500), vec![0x2100, 0x2500]),
            (0x2100, branch(0x2400), vec![0x2200, 0x2400]), // internal skip to latch
            (0x2200, vec![Op::Jump { target: 0x2300 }], vec![0x2300]),
            (0x2300, vec![Op::Jump { target: 0x2400 }], vec![0x2400]),
            (0x2400, branch(0x2100), vec![0x2100, 0x2500]), // bottom latch / exit
            (0x2500, vec![Op::Nop], vec![0x2600]),          // required result prefix
            (0x2600, vec![Op::Return], vec![]),
        ]);
        let bottom_region = recover_for(&bottom_tested);
        fn owns_block(region: &Region, target: usize) -> bool {
            match region {
                Region::Block(block) => *block == target,
                Region::Seq(parts) => parts.iter().any(|part| owns_block(part, target)),
                Region::IfThen { then_r, .. }
                | Region::While { body: then_r, .. }
                | Region::DoWhile { body: then_r, .. }
                | Region::MultiExitLoop { body: then_r, .. } => owns_block(then_r, target),
                Region::IfThenElse { then_r, else_r, .. } => {
                    owns_block(then_r, target) || owns_block(else_r, target)
                }
                Region::Switch {
                    arms,
                    formal_default,
                    ..
                } => {
                    arms.iter().any(|arm| owns_block(arm, target))
                        || formal_default
                            .as_deref()
                            .is_some_and(|default| owns_block(default, target))
                }
                Region::RawLoop { blocks, .. } | Region::Unstructured(blocks) => {
                    blocks.contains(&target)
                }
                Region::Goto(_) => false,
            }
        }
        fn loop_is_followed_by_block(region: &Region, target: usize) -> bool {
            match region {
                Region::Seq(parts) => {
                    (0..parts.len()).any(|index| {
                        contains_structured_loop(&parts[index])
                            && parts[index + 1..]
                                .iter()
                                .any(|later| owns_block(later, target))
                    }) || parts
                        .iter()
                        .any(|part| loop_is_followed_by_block(part, target))
                }
                Region::IfThen { then_r, .. }
                | Region::While { body: then_r, .. }
                | Region::DoWhile { body: then_r, .. }
                | Region::MultiExitLoop { body: then_r, .. } => {
                    loop_is_followed_by_block(then_r, target)
                }
                Region::IfThenElse { then_r, else_r, .. } => {
                    loop_is_followed_by_block(then_r, target)
                        || loop_is_followed_by_block(else_r, target)
                }
                Region::Switch {
                    arms,
                    formal_default,
                    ..
                } => {
                    arms.iter()
                        .any(|arm| loop_is_followed_by_block(arm, target))
                        || formal_default
                            .as_deref()
                            .is_some_and(|default| loop_is_followed_by_block(default, target))
                }
                Region::Block(_)
                | Region::Goto(_)
                | Region::RawLoop { .. }
                | Region::Unstructured(_) => false,
            }
        }
        assert!(
            loop_is_followed_by_block(&bottom_region, 5),
            "the bottom-tested loop exit lost its result prefix: {bottom_region:#?}"
        );
        assert!(verify_structure(&bottom_tested, &compute_ssa(&bottom_tested)).is_empty());
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
                Region::While { body, .. }
                | Region::DoWhile { body, .. }
                | Region::MultiExitLoop { body, .. } => assert_no_unstructured(body),
                Region::RawLoop { .. } => {}
                Region::Switch { arms, .. } => {
                    arms.iter().for_each(assert_no_unstructured);
                }
                Region::Goto(_) => {}
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
    fn switch_shape_with_three_arms_recognized() {
        //   B0 dispatch → B1, B2, B3 (3 arms)
        //   B1, B2, B3 each → B4 (join)
        //   B4: return
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100, 0x1200, 0x1300]),
            (0x1100, vec![Op::Nop], vec![0x1400]),
            (0x1200, vec![Op::Nop], vec![0x1400]),
            (0x1300, vec![Op::Nop], vec![0x1400]),
            (0x1400, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        match &r {
            Region::Seq(parts) => {
                assert!(parts.len() >= 2);
                match &parts[0] {
                    Region::Switch {
                        dispatch,
                        arms,
                        join,
                        ..
                    } => {
                        assert_eq!(*dispatch, 0);
                        assert_eq!(arms.len(), 3);
                        assert_eq!(*join, Some(4));
                    }
                    other => panic!("expected Switch; got {:?}", other),
                }
            }
            other => panic!("expected Seq; got {:?}", other),
        }
    }

    #[test]
    fn nested_switch_arms_stop_at_the_enclosing_conditional_join() {
        // Clang -O0 jump-table dispatch is guarded by an out-of-range branch:
        //
        //        b0
        //       /  \
        //   default b5   dispatch b1 -> b2,b3,b4
        //       \          /   |   /
        //                 join b6 -> return
        //
        // The switch has no join dominated by its dispatch because b5 also
        // reaches b6.  Nevertheless b6 is the enclosing if/else join and no
        // switch arm owns it.  Letting the first case consume b6 nests the one
        // shared return in that case and makes every default path fall off the
        // emitted C function.
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![Op::CondJump {
                    cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                    target: 0x1500,
                    inverted: false,
                }],
                vec![0x1100, 0x1500],
            ),
            (0x1100, vec![Op::Nop], vec![0x1200, 0x1300, 0x1400]),
            (0x1200, vec![Op::Nop], vec![0x1600]),
            (0x1300, vec![Op::Nop], vec![0x1600]),
            (0x1400, vec![Op::Nop], vec![0x1600]),
            (0x1500, vec![Op::Nop], vec![0x1600]),
            (0x1600, vec![Op::Return], vec![]),
        ]);

        let region = recover_for(&lf);
        let Region::Seq(parts) = &region else {
            panic!("the shared join must be emitted after the conditional: {region:#?}")
        };
        assert!(
            matches!(parts.last(), Some(Region::Block(6))),
            "{region:#?}"
        );

        fn find_switch(region: &Region) -> Option<&Region> {
            match region {
                Region::Switch { .. } => Some(region),
                Region::Seq(parts) => parts.iter().find_map(find_switch),
                Region::IfThen { then_r, .. } => find_switch(then_r),
                Region::IfThenElse { then_r, else_r, .. } => {
                    find_switch(then_r).or_else(|| find_switch(else_r))
                }
                Region::While { body, .. }
                | Region::DoWhile { body, .. }
                | Region::MultiExitLoop { body, .. } => find_switch(body),
                Region::Block(_)
                | Region::Goto(_)
                | Region::RawLoop { .. }
                | Region::Unstructured(_) => None,
            }
        }
        let Some(Region::Switch { arms, join, .. }) = find_switch(&region) else {
            panic!("expected nested switch: {region:#?}")
        };
        assert_eq!(
            *join,
            Some(6),
            "the switch must expose its enclosing shared continuation"
        );
        assert!(
            arms.iter().all(|arm| !arm.blocks().contains(&6)),
            "the enclosing join must not be consumed by a switch case: {region:#?}"
        );
    }

    #[test]
    fn guarded_switch_with_terminating_case_keeps_its_partial_join_outside() {
        // The range guard can bypass the dispatch directly to b5. Most cases
        // also reach b5, while one case returns through b6.  Since b5 does not
        // post-dominate the returning case, a global post-dominator search
        // misses the source shape:
        //
        //     if (in_range) { switch (...) { ...; case 3: return; } }
        //     b5: latch/update;
        //
        // Treating it as if/else places b5 in the bypass arm and forces every
        // continuing case to goto into that sibling arm.
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![Op::CondJump {
                    cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                    target: 0x1500,
                    inverted: false,
                }],
                vec![0x1100, 0x1500],
            ),
            (0x1100, vec![Op::Nop], vec![0x1200, 0x1300, 0x1400]),
            (0x1200, vec![Op::Jump { target: 0x1500 }], vec![0x1500]),
            (0x1300, vec![Op::Jump { target: 0x1500 }], vec![0x1500]),
            (0x1400, vec![Op::Return], vec![]),
            (0x1500, vec![Op::Nop], vec![0x1600]),
            (0x1600, vec![Op::Return], vec![]),
        ]);

        let region = recover_for(&lf);
        let Region::Seq(parts) = &region else {
            panic!("expected guarded switch followed by its join: {region:#?}")
        };
        let Some(Region::IfThen {
            then_r,
            join: Some(5),
            ..
        }) = parts.first()
        else {
            panic!("expected one-armed guarded switch: {region:#?}")
        };
        assert!(
            matches!(then_r.as_ref(), Region::Switch { join: Some(5), .. }),
            "the switch and guard must share b5 as their continuation: {region:#?}"
        );
        assert!(
            matches!(parts.get(1), Some(Region::Block(5))),
            "{region:#?}"
        );
    }

    #[test]
    fn switch_shape_arms_with_terminating_returns() {
        //   B0 dispatch → B1, B2, B3
        //   each Bi: return  (no shared join)
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100, 0x1200, 0x1300]),
            (0x1100, vec![Op::Return], vec![]),
            (0x1200, vec![Op::Return], vec![]),
            (0x1300, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        match &r {
            Region::Switch {
                dispatch,
                arms,
                join,
                ..
            } => {
                assert_eq!(*dispatch, 0);
                assert_eq!(arms.len(), 3);
                assert_eq!(*join, None);
            }
            other => panic!("expected Switch with join=None; got {:?}", other),
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
                total_timeout_ms: 0,
            },
        );
        for f in &funcs {
            if let Ok(lf) = lift_function_from_bytes(&data, f, Arch::X86_64) {
                let ssa = compute_ssa(&lf);
                let r = recover(&lf, &ssa);
                // Every block must be covered at least once.
                let covered: std::collections::HashSet<usize> = r.blocks().into_iter().collect();
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

    #[test]
    fn verify_structure_clean_on_recovered_diamond() {
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100, 0x1200]),
            (0x1100, vec![Op::Nop], vec![0x1300]),
            (0x1200, vec![Op::Nop], vec![0x1300]),
            (0x1300, vec![Op::Return], vec![]),
        ]);
        let ssa = compute_ssa(&lf);
        assert!(verify_structure(&lf, &ssa).is_empty());
    }

    #[test]
    fn short_circuit_shared_return_is_faithful_without_goto() {
        // The `x>0 && y>0` shape: two conditionals share a common false block.
        //   B0 -> {B1, Bfalse}   B1 -> {Btrue, Bfalse}
        //   Btrue -> Bend  Bfalse -> Bend  Bend: return
        // Bfalse and Bend form a linear return chain.  It may be duplicated
        // into both false arms, but it must neither be dropped nor represented
        // as a cross-arm goto.
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100, 0x1300]), // B0 cond
            (0x1100, vec![Op::Nop], vec![0x1200, 0x1300]), // B1 cond
            (0x1200, vec![Op::Nop], vec![0x1400]),         // Btrue
            (0x1300, vec![Op::Nop], vec![0x1400]),         // Bfalse (shared)
            (0x1400, vec![Op::Return], vec![]),            // Bend
        ]);
        let ssa = compute_ssa(&lf);
        let region = recover(&lf, &ssa);
        assert!(
            verify_structure(&lf, &ssa).is_empty(),
            "short-circuit region must remain faithful after return cloning; got {:?}",
            verify_structure(&lf, &ssa)
        );
        // The shared false block (index 3) is cloned into both guards and no
        // longer needs a cross-region goto.
        fn has_goto(r: &Region, target: usize) -> bool {
            match r {
                Region::Goto(b) => *b == target,
                Region::Seq(v) => v.iter().any(|p| has_goto(p, target)),
                Region::IfThen { then_r, .. } => has_goto(then_r, target),
                Region::IfThenElse { then_r, else_r, .. } => {
                    has_goto(then_r, target) || has_goto(else_r, target)
                }
                Region::While { body, .. } => has_goto(body, target),
                Region::Switch { arms, .. } => arms.iter().any(|a| has_goto(a, target)),
                _ => false,
            }
        }
        assert!(
            !has_goto(&region, 3),
            "unexpected shared-return goto: {region:?}"
        );
        assert!(
            region.blocks().iter().filter(|&&block| block == 3).count() >= 2,
            "both false guards must retain the shared result block: {region:#?}"
        );
    }

    #[test]
    fn long_short_circuit_guard_chain_is_not_mistaken_for_a_switch_tree() {
        // Source-level validation commonly lowers to a long ordered chain:
        //
        //   if (p == NULL || q == NULL || rows < 0 || rows > limit || ...) {
        //       return 0;
        //   }
        //
        // Every guard jumps to the same return block and otherwise advances to
        // the next guard.  Four guards used to trigger a count-only heuristic
        // intended for GCC comparison trees, leaving this faithful
        // short-circuit shape as nested if/else plus gotos.  The continuation
        // chain is the distinguishing fact: unlike a switch tree, every
        // conditional in this chain has the same exit successor.
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1010, 0x1060]),
            (0x1010, vec![Op::Nop], vec![0x1020, 0x1060]),
            (0x1020, vec![Op::Nop], vec![0x1030, 0x1060]),
            (0x1030, vec![Op::Nop], vec![0x1040, 0x1060]),
            (0x1040, vec![Op::Nop], vec![0x1050, 0x1060]),
            (0x1050, vec![Op::Return], vec![]),
            (0x1060, vec![Op::Return], vec![]),
        ]);

        let ssa = compute_ssa(&lf);
        let region = recover(&lf, &ssa);
        let rendered = format!("{region:#?}");
        assert!(
            !rendered.contains("Goto(6)"),
            "ordered guards should clone the shared return, not jump across regions: {rendered}"
        );
        assert!(
            region.blocks().iter().filter(|&&block| block == 6).count() >= 5,
            "every ordered guard must retain its short-circuit return: {rendered}"
        );
        assert!(
            verify_structure(&lf, &ssa).is_empty(),
            "guard-chain recovery must retain every CFG edge: {:?}",
            verify_structure(&lf, &ssa)
        );
    }

    #[test]
    fn relocated_linear_fallthrough_to_an_owned_join_becomes_a_goto() {
        use crate::ir::types::{Flag, VReg};

        let cj = |target: u64| Op::CondJump {
            cond: VReg::Flag(Flag::S),
            target,
            inverted: false,
        };
        // The first arm owns B3 before the second arm is structured.  Inside
        // that second arm B5 reaches B3 by machine-code adjacency, not an
        // explicit jump.  Once B5 is nested in C, B3 is no longer lexically
        // next, so the linear edge must be materialised as Goto(3).
        //
        // This is the reduced shape of Clang O2 loop_return_on_neg: its i=6
        // negative arm fell through to a shared result block in the binary but
        // fell out of a nested C `if`, returning an uninitialised value.
        let lf = mk_cfg(vec![
            (0x1000, vec![cj(0x1100)], vec![0x1100, 0x1200]), // B0
            (0x1100, vec![Op::Nop], vec![0x1300]),            // B1 -> shared
            (0x1200, vec![cj(0x1500)], vec![0x1500, 0x1600]), // B2
            (0x1300, vec![Op::Nop], vec![0x1400]),            // B3 shared
            (0x1400, vec![Op::Return], vec![]),               // B4 epilogue
            (0x1500, vec![Op::Nop], vec![0x1300]),            // B5 linear -> B3
            (0x1600, vec![Op::Jump { target: 0x1400 }], vec![0x1400]), // B6 bypass
        ]);

        fn has_goto(r: &Region, target: usize) -> bool {
            match r {
                Region::Goto(block) => *block == target,
                Region::Seq(parts) => parts.iter().any(|part| has_goto(part, target)),
                Region::IfThen { then_r, .. } => has_goto(then_r, target),
                Region::IfThenElse { then_r, else_r, .. } => {
                    has_goto(then_r, target) || has_goto(else_r, target)
                }
                Region::While { body, .. }
                | Region::DoWhile { body, .. }
                | Region::MultiExitLoop { body, .. } => has_goto(body, target),
                Region::Switch { arms, .. } => arms.iter().any(|arm| has_goto(arm, target)),
                Region::Block(_) | Region::RawLoop { .. } | Region::Unstructured(_) => false,
            }
        }

        let region = recover_for(&lf);
        assert!(
            has_goto(&region, 3),
            "relocated linear edge to B3 was dropped: {region:#?}"
        );
    }

    /// Textbook irreducible CFG: entry branches directly into EITHER of two
    /// blocks that form a 2-cycle between themselves, so neither block
    /// dominates the other (the entry can reach each one without passing
    /// through the other). This is exactly "two gotos into one loop body from
    /// non-dominating branches" — the shape a source-level `if (c) goto mid;`
    /// jumping into the middle of a `while` produces.
    ///
    ///   0 (entry) -> 1 (fallthrough) | 2 (taken)
    ///   1 -> 2 (jump)
    ///   2 -> 1 (taken) | 3 (fallthrough exit)
    ///   3 -> return
    ///
    /// No edge in the {1,2} cycle is a dominance-based back edge (`to`
    /// dominates `from`): `1` does not dominate `2` (0->2 reaches it without
    /// passing through 1) and `2` does not dominate `1` (0->1 reaches it
    /// without passing through 2). No single block can serve as the loop's
    /// header, which is the defining property of irreducibility.
    fn irreducible_two_entry_cycle() -> LlirFunction {
        use crate::ir::types::Flag;
        let cj = |target: u64| Op::CondJump {
            cond: VReg::Flag(Flag::Z),
            target,
            inverted: false,
        };
        mk_cfg(vec![
            (0x1000, vec![cj(0x1200)], vec![0x1100, 0x1200]), // B0 entry
            (0x1100, vec![Op::Jump { target: 0x1200 }], vec![0x1200]), // B1
            (0x1200, vec![cj(0x1100)], vec![0x1300, 0x1100]), // B2
            (0x1300, vec![Op::Return], vec![]),               // B3 exit
        ])
    }

    /// Ground truth: confirm the fixture is genuinely irreducible before
    /// trusting any claim about how the structurer handles it. Neither
    /// direction of the {1,2} cycle is a dominance-based back edge.
    #[test]
    fn the_two_entry_cycle_fixture_really_is_irreducible() {
        let lf = irreducible_two_entry_cycle();
        let ssa = compute_ssa(&lf);
        let cfg = Cfg::from(&lf, &ssa);
        let one_to_two_is_back = cfg.edges[1].iter().any(|e| e.to == 2 && e.back);
        let two_to_one_is_back = cfg.edges[2].iter().any(|e| e.to == 1 && e.back);
        assert!(
            !one_to_two_is_back && !two_to_one_is_back,
            "the {{1,2}} cycle must have no dominance-based back edge, or this \
             fixture is not actually irreducible: edges[1]={:?} edges[2]={:?}",
            cfg.edges[1],
            cfg.edges[2]
        );
    }

    /// RED->GREEN target for the roadmap item "Preserve irreducible and
    /// unresolved flow with explicit goto/indirect fallback rather than
    /// inventing structure" (`docs/history/design/decompiler-roadmap-2026-08-13.md`,
    /// "Complete CFG and semantic structuring") and design rule 8 ("A failed
    /// proof keeps a lower-level expression, explicit unknown, or honest goto.
    /// It does not guess.").
    ///
    /// `recover_verified_with_health` is the single production entry point
    /// (its own doc comment says so). On a graph no `While`/`DoWhile`/`RawLoop`
    /// pattern can honestly own, it must fall back to the complete labelled
    /// CFG rather than silently pick a header and drop or invent an edge to
    /// make one arm's cycle look ordinary.
    #[test]
    fn two_non_dominating_entries_into_a_cycle_preserve_lossless_fallback() {
        let lf = irreducible_two_entry_cycle();
        let ssa = compute_ssa(&lf);
        let (region, health) = recover_verified_with_health(&lf, &ssa);

        // The region must be the complete labelled-CFG fallback, not a
        // speculative loop shape that happened to pass verification by
        // dropping or inventing an edge.
        assert!(
            matches!(&region, Region::Unstructured(blocks) if blocks.len() == 4),
            "expected the lossless labelled-CFG fallback over all 4 blocks, \
             got {region:#?}"
        );
        assert_eq!(
            health.structure_fallbacks, 1,
            "the verified-recovery fallback must be recorded, not silent: {health:?}"
        );
        assert_eq!(
            health.uncovered_cfg_edges, 0,
            "the fallback region must not drop a real edge: {health:?}"
        );
        assert_eq!(
            health.invented_cfg_edges, 0,
            "the fallback region must not invent an edge: {health:?}"
        );

        // Re-derive edge accounting independently of the immutable counters
        // above, against the SELECTED region actually returned — this is the
        // module `recover_verified_with_health` itself uses to decide whether
        // to fall back, run again here so the test does not merely trust the
        // health struct's own arithmetic.
        let cfg = Cfg::from(&lf, &ssa);
        let acct = crate::ir::structure_accounting::account(&cfg.edges, &cfg.preds, 0, &region);
        assert_eq!(
            acct,
            Vec::new(),
            "the selected fallback region must account for every block and \
             every edge with nothing dropped, duplicated, or invented: {acct:?}"
        );
    }

    /// Negative control: the SAME two-block cycle, entered from only ONE
    /// place, is ordinary reducible flow and must NOT hit the labelled-CFG
    /// fallback. This pins that the fallback above is triggered by
    /// irreducibility specifically — a non-dominating second entry into the
    /// cycle — and not merely by "a cycle exists between two blocks".
    #[test]
    fn a_single_entry_into_the_same_two_block_cycle_structures_normally() {
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Jump { target: 0x1100 }], vec![0x1100]), // B0 entry
            (0x1100, vec![Op::Jump { target: 0x1200 }], vec![0x1200]), // B1
            (
                0x1200,
                vec![Op::CondJump {
                    cond: VReg::Flag(crate::ir::types::Flag::Z),
                    target: 0x1100,
                    inverted: false,
                }],
                vec![0x1300, 0x1100],
            ), // B2
            (0x1300, vec![Op::Return], vec![]),                        // B3 exit
        ]);
        let ssa = compute_ssa(&lf);
        let (region, health) = recover_verified_with_health(&lf, &ssa);
        assert!(
            !matches!(&region, Region::Unstructured(blocks) if blocks.len() == lf.blocks.len()),
            "a single, dominating entry into the loop must not need the total \
             labelled-CFG fallback: {region:#?}"
        );
        assert_eq!(
            health.structure_fallbacks, 0,
            "reducible flow must not report a structure fallback: {health:?}"
        );
    }
}
