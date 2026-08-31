//! Conditional shape detection: the if-then / if-then-else recogniser and the
//! arm-polarity rule it depends on.
//!
//! The sibling of [`super::loop_shape`] and [`super::switch_shape`], and the
//! third of the three shapes `super::build` tries. One entry point,
//! [`detect_if_shape`], walks a descending ladder of diamond shapes — the
//! textbook single-predecessor diamond first, then the cloned-epilogue,
//! terminating-arm and post-dominator-join variants that real optimised code
//! produces — and returns the first that it can prove absorbs the whole
//! conditional. It changes when a new conditional shape is recognised, or when
//! an existing one is proven unsafe.
//!
//! [`invert_for`] is here rather than in the builder because arm polarity is a
//! property of this shape: every one of its ten callers is a branch of the
//! ladder choosing which successor becomes the `then` arm.

use std::collections::HashSet;

use super::cfg::Cfg;
use super::path_predicates::{
    can_reach, contains_multiway_before, cyclic_body_exits_only_to_join, every_path_reaches_join,
    every_path_reaches_join_or_terminates, is_natural_loop_distinguished_exit, shared_return_chain,
};
use super::region::Region;
use super::{build, build_arm};

/// Whether the lowered condition at block `cond` must be negated when
/// `then_entry` is used as the `then` arm. The raw condition is true when the
/// branch is *taken* (jumps to `cond_taken`); if `then_entry` is instead the
/// fall-through arm, `if (cond) { then_entry }` would run it on the wrong edge,
/// so the condition is inverted. This is THE fix for the polarity bug where arms
/// were chosen by sorted block index rather than the taken edge.
fn invert_for(cfg: &Cfg, cond: usize, then_entry: usize) -> bool {
    cfg.cond_taken[cond] != Some(then_entry)
}

/// Recognise an if-then / if-then-else diamond rooted at `cond`.
///
/// Returns `Some((region, after))` when we can structurally absorb the whole
/// conditional and continue at `after` (the join block, or None if one of
/// the arms exits outright).
pub(super) fn detect_if_shape(
    cond: usize,
    cfg: &Cfg,
    visited: &mut HashSet<usize>,
    stop_at: Option<usize>,
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
        let invert = invert_for(cfg, cond, t);
        // Mark cond consumed, recurse on arms.
        visited.insert(cond);
        let then_r = build_arm(t, cfg, visited, Some(join));
        let else_r = build_arm(e, cfg, visited, Some(join));
        return Some((
            Region::IfThenElse {
                cond,
                then_r: Box::new(then_r),
                else_r: Box::new(else_r),
                join: Some(join),
                invert,
            },
            Some(join),
        ));
    }

    // --- if-then (no else) -------------------------------------------------
    // One successor is the join directly; the other is an acyclic body whose
    // non-terminating paths all reach that join. The body is often one block,
    // but a comparison ladder inside a loop can contain several more branches.
    // Requiring a one-block body strands those fallthrough blocks outside the
    // loop and eventually renders them after the function return.
    for &(body, join) in &[(t, e), (e, t)] {
        let simple_body = cfg.succs[body] == vec![join];
        let proven_complex_body = !cfg.succs[join].is_empty()
            && (every_path_reaches_join(body, join, cfg)
                || cyclic_body_exits_only_to_join(body, join, cond, cfg));
        let body_rejoins = cfg.preds[body] == vec![cond] && (simple_body || proven_complex_body);
        if body_rejoins && cfg.preds[join].contains(&cond) {
            let invert = invert_for(cfg, cond, body);
            visited.insert(cond);
            let then_r = build(body, cfg, visited, Some(join));
            return Some((
                Region::IfThen {
                    cond,
                    then_r: Box::new(then_r),
                    join: Some(join),
                    invert,
                },
                Some(join),
            ));
        }
    }

    // --- terminal guard with a terminal continuation -----------------------
    // Both direct arms can be CFG terminals even though one is semantically a
    // non-returning guard and the other is an ordinary function tail. Prefer
    // the unique arm without an explicit machine return as the one-arm body.
    // If both have the same terminal kind, use the semantic taken edge as the
    // deterministic tie-breaker. Successor-vector order is never branch truth.
    let t_terminates = cfg.preds[t] == vec![cond] && cfg.succs[t].is_empty();
    let e_terminates = cfg.preds[e] == vec![cond] && cfg.succs[e].is_empty();
    if t_terminates && e_terminates {
        let body_and_cont = match (cfg.ends_in_return[t], cfg.ends_in_return[e]) {
            (false, true) => Some((t, e)),
            (true, false) => Some((e, t)),
            _ => match cfg.cond_taken[cond] {
                Some(taken) if taken == t => Some((t, e)),
                Some(taken) if taken == e => Some((e, t)),
                _ => None,
            },
        };
        if let Some((body, cont)) = body_and_cont {
            let invert = invert_for(cfg, cond, body);
            visited.insert(cond);
            let then_r = build(body, cfg, visited, None);
            return Some((
                Region::IfThen {
                    cond,
                    then_r: Box::new(then_r),
                    join: None,
                    invert,
                },
                Some(cont),
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
            let invert = invert_for(cfg, cond, body);
            visited.insert(cond);
            let then_r = build(body, cfg, visited, None);
            return Some((
                Region::IfThen {
                    cond,
                    then_r: Box::new(then_r),
                    join: None,
                    invert,
                },
                Some(cont),
            ));
        }
    }

    // --- if-then with shared return epilogue (#192) -------------------------
    // The richer shape: one arm reaches a return epilogue shared by multiple
    // sites (e.g. `L_zero: xor eax,eax; L_ret: ret`).  Optimised Clang commonly
    // splits the returned-value setup from the bare return, so requiring the
    // direct successor itself to be terminal leaves a cross-region goto even
    // though the entire successor chain is a source-level early return.
    //
    // Clone-inline the proven linear return chain into this if-then's body.
    // A prefix which is a natural loop header's designated exit remains
    // unvisited because the normal loop continuation must emit it.  Clang
    // `fib` shares an `add` block between an early base case and precisely that
    // exit; claiming it drops the loop result.  A secondary body exit whose
    // predecessors are all guards, such as `list_find`'s null-result block, has
    // no such continuation owner and must be marked represented or structural
    // accounting correctly rejects the orphan.
    //
    // The duplicated block references cause the AST lowerer to render the
    // epilogue once per branch site, which is the right source semantics: each
    // machine edge is conceptually `if (cond) { return value; }`.
    for &(body, cont) in &[(t, e), (e, t)] {
        // A range guard whose other arm is a multi-way dispatch owns a partial
        // switch join, not an early-return sibling.  The guarded-switch
        // detector needs that continuation intact to keep its cases and bypass
        // path in one region.
        if cfg.is_switch_dispatch(cont) {
            continue;
        }
        if let Some(chain) = shared_return_chain(body, cfg) {
            if chain.contains(&cont) {
                continue;
            }
            // Clone every proven return edge. The AST switch-ladder pass can
            // reunify exact cloned defaults, while a predecessor count alone
            // cannot distinguish a switch tree from validation or loop exits.
            let invert = invert_for(cfg, cond, body);
            visited.insert(cond);
            let prefix_is_owned_by_guards = cfg.preds[body]
                .iter()
                .all(|predecessor| cfg.succs[*predecessor].len() == 2);
            if prefix_is_owned_by_guards && !is_natural_loop_distinguished_exit(body, cfg) {
                visited.extend(chain[..chain.len() - 1].iter().copied());
            }
            let then_r = if let [only] = chain.as_slice() {
                Region::Block(*only)
            } else {
                Region::Seq(chain.into_iter().map(Region::Block).collect())
            };
            return Some((
                Region::IfThen {
                    cond,
                    then_r: Box::new(then_r),
                    join: None,
                    invert,
                },
                Some(cont),
            ));
        }
    }

    // --- optional preheader feeding a shared natural loop -----------------
    // Optimisers commonly peel one iteration or initialise an odd/even lane in
    // only one arm, after which both arms enter the same loop header.  A side
    // exit from that optional preheader (for example `if (n == 1) return`) makes
    // the function epilogue the condition's global post-dominator, even though
    // the loop header is the local join for every continuing path.  Choosing the
    // epilogue nests the loop inside only the direct arm and makes the setup arm
    // skip all remaining iterations.
    for &(body, join) in &[(t, e), (e, t)] {
        let join_is_loop_header = cfg.preds[join]
            .iter()
            .copied()
            .any(|tail| cfg.dominates(join, tail));
        if join_is_loop_header
            && cfg.preds[body] == vec![cond]
            && can_reach(body, join, cfg)
            && every_path_reaches_join_or_terminates(body, join, cfg)
        {
            let invert = invert_for(cfg, cond, body);
            visited.insert(cond);
            let then_r = build(body, cfg, visited, Some(join));
            return Some((
                Region::IfThen {
                    cond,
                    then_r: Box::new(then_r),
                    join: Some(join),
                    invert,
                },
                Some(join),
            ));
        }
    }

    // --- guarded multi-way body with a partial continuation ---------------
    // A compiler guards a jump table with an out-of-range edge directly to
    // the common latch/epilogue. Most cases reach that same block, but a case
    // may return early. The continuation therefore does not post-dominate the
    // dispatch, even though every non-terminating path reaches it. This is a
    // one-armed `if (in_range) switch (...)` followed by the continuation, not
    // an if/else whose sibling arm owns the continuation.
    for &(body, join) in &[(t, e), (e, t)] {
        let join_is_formal_switch_default = cfg.is_switch_dispatch(body)
            && cfg.succs[body].contains(&join)
            && cfg.edges[cond].iter().any(|edge| {
                edge.to == join && edge.kind == crate::ir::cfg_edges::EdgeKind::SwitchDefault
            });
        if !join_is_formal_switch_default
            && cfg.succs[body].len() >= 3
            && cfg.preds[body] == vec![cond]
            && cfg.preds[join].contains(&cond)
            && can_reach(body, join, cfg)
            && every_path_reaches_join_or_terminates(body, join, cfg)
        {
            let invert = invert_for(cfg, cond, body);
            visited.insert(cond);
            let then_r = build(body, cfg, visited, Some(join));
            return Some((
                Region::IfThen {
                    cond,
                    then_r: Box::new(then_r),
                    join: Some(join),
                    invert,
                },
                Some(join),
            ));
        }
    }

    // (switch detection lives in detect_switch_shape — invoked by build()
    // before falling through to the default block path, since this fn is
    // only called for 2-successor blocks.)

    // --- if-then-else where both arms terminate (#192) ---------------------
    // Both arms exit the function; there is no continuation. We emit an
    // IfThenElse with join=None and signal the outer build to stop.
    if t_terminates && e_terminates {
        let invert = invert_for(cfg, cond, t);
        visited.insert(cond);
        let then_r = build(t, cfg, visited, None);
        let else_r = build(e, cfg, visited, None);
        return Some((
            Region::IfThenElse {
                cond,
                then_r: Box::new(then_r),
                else_r: Box::new(else_r),
                join: None,
                invert,
            },
            None,
        ));
    }

    // --- General conditional via immediate post-dominator ------------------
    // The arms reconverge only at a *distant* join (not an immediate diamond):
    // the classic gcc -O0 comparison-ladder / switch shape, where each case
    // body jumps to a shared end block. Structuring it against the post-dominator
    // collapses the whole ladder into nested if/else with a single exit instead
    // of goto soup. Runs only after every tighter pattern above has declined.
    let mut distant_join = cfg.ipostdom[cond];
    let mut bounded_by_enclosing_region = false;
    if let (Some(boundary), Some(join)) = (stop_at, distant_join) {
        // An immediate post-dominator may lie beyond the region currently being
        // built (most importantly, a function epilogue beyond a loop latch).
        // In that case it is not this conditional's local join: use the region
        // boundary when at least one arm continues there. The other arm may
        // legitimately terminate early.
        if join != boundary
            && !can_reach(join, boundary, cfg)
            && (can_reach(t, boundary, cfg) || can_reach(e, boundary, cfg))
            && (!cfg.dominates(boundary, cond)
                || contains_multiway_before(t, boundary, cfg)
                || contains_multiway_before(e, boundary, cfg))
        {
            distant_join = Some(boundary);
            bounded_by_enclosing_region = true;
        }
    }
    if let Some(join) = distant_join {
        if join != cond && t != join && e != join {
            // Order the arms by the branch's taken target so the rendered
            // condition polarity is correct: `if (cond)` must guard the arm the
            // branch jumps to when taken. Without this the ladder inverts (block
            // address order is not taken/fallthrough order).
            let (then_a, else_a) = match cfg.cond_taken[cond] {
                Some(tk) if tk == e => (e, t),
                _ => (t, e),
            };
            let invert = invert_for(cfg, cond, then_a);
            visited.insert(cond);
            let (then_r, else_r) = if bounded_by_enclosing_region {
                // Paths that leave a bounded region (a return from inside a
                // loop is the common case) may include a shared function
                // epilogue. Render that terminating path here, but only commit
                // ownership of blocks which can rejoin the region boundary;
                // otherwise outer paths lose their one real epilogue.
                let mut scoped_visited = visited.clone();
                let then_r = build_arm(then_a, cfg, &mut scoped_visited, Some(join));
                let else_r = build_arm(else_a, cfg, &mut scoped_visited, Some(join));
                visited.extend(
                    scoped_visited
                        .into_iter()
                        .filter(|&block| can_reach(block, join, cfg)),
                );
                (then_r, else_r)
            } else {
                (
                    build_arm(then_a, cfg, visited, Some(join)),
                    build_arm(else_a, cfg, visited, Some(join)),
                )
            };
            return Some((
                Region::IfThenElse {
                    cond,
                    then_r: Box::new(then_r),
                    else_r: Box::new(else_r),
                    join: Some(join),
                    invert,
                },
                Some(join),
            ));
        }
    }

    None
}
