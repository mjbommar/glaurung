//! The lossless-fallback policy: every rule under which a speculative region
//! tree is rejected in favour of the complete labelled CFG.
//!
//! Three of these run *before* the builder, over the CFG
//! ([`has_multi_latch_loop_with_distinct_exits`],
//! [`has_loop_conditional_with_join_beyond_loop`],
//! [`has_inner_loop_exit_that_reenters_via_outer_cycle`]); the other three run
//! *after* it, over the tree the builder produced — [`contains_switch`] and
//! [`contains_structured_loop`] scope the leftover guard, and
//! [`structure_accounting_is_unsound`] is the shared classifier both that guard
//! and the verified entry point apply to an accounting result. They are one
//! owner because they
//! encode one judgement — which shapes the region algebra cannot yet express
//! without moving or dropping control flow — and they change for one reason:
//! that algebra grows a shape, or a new unrepresentable one is found. Every
//! doc comment below names the algebra gap it is waiting on.
//!
//! Nothing here builds a region or claims a block. A `true` from any of them
//! costs the whole function its structure, so each is written to be a proof of
//! the unsafe shape rather than a heuristic for it.

use std::collections::HashSet;

use super::cfg::Cfg;
use super::loop_shape::loop_break_shape;
use super::path_predicates::can_reach;
use super::region::Region;

/// Whether accounting found a semantic control-flow defect rather than a
/// retained quality diagnostic.
///
/// Shared terminal cloning and explicit gotos can duplicate a block reference
/// while preserving every executable edge. Both the early verified fallback
/// and the late leftover guard must classify those findings identically; using
/// `!account(...).is_empty()` in only one place erased otherwise verified loops.
pub(super) fn structure_accounting_is_unsound(
    accounting: &[crate::ir::structure_accounting::AccountError],
) -> bool {
    accounting.iter().any(|error| {
        use crate::ir::structure_accounting::AccountError;
        matches!(
            error,
            AccountError::BlockDropped { .. }
                | AccountError::EdgeUnaccounted { .. }
                | AccountError::BackEdgeUnowned { .. }
                | AccountError::ImpliedEdgeAbsent { .. }
                | AccountError::GotoTargetMissing { .. }
                | AccountError::SwitchArmOutsideLoop { .. }
        )
    })
}

pub(super) fn contains_switch(region: &Region) -> bool {
    match region {
        Region::Switch { .. } => true,
        Region::Seq(parts) => parts.iter().any(contains_switch),
        Region::IfThen { then_r, .. }
        | Region::While { body: then_r, .. }
        | Region::DoWhile { body: then_r, .. }
        | Region::MultiExitLoop { body: then_r, .. }
        | Region::Borrowed(then_r) => contains_switch(then_r),
        Region::IfThenElse { then_r, else_r, .. } => {
            contains_switch(then_r) || contains_switch(else_r)
        }
        Region::Block(_) | Region::Goto(_) | Region::RawLoop { .. } | Region::Unstructured(_) => {
            false
        }
    }
}

pub(super) fn contains_structured_loop(region: &Region) -> bool {
    match region {
        Region::While { .. } | Region::DoWhile { .. } | Region::MultiExitLoop { .. } => true,
        Region::Seq(parts) => parts.iter().any(contains_structured_loop),
        Region::IfThen { then_r, .. } => contains_structured_loop(then_r),
        Region::Borrowed(inner) => contains_structured_loop(inner),
        Region::IfThenElse { then_r, else_r, .. } => {
            contains_structured_loop(then_r) || contains_structured_loop(else_r)
        }
        Region::Switch {
            arms,
            formal_default,
            ..
        } => {
            arms.iter().any(contains_structured_loop)
                || formal_default
                    .as_deref()
                    .is_some_and(contains_structured_loop)
        }
        Region::Block(_) | Region::Goto(_) | Region::RawLoop { .. } | Region::Unstructured(_) => {
            false
        }
    }
}

/// An inner natural loop can return through its header while its latch takes an
/// exhaustion edge, executes an outer-loop reload/reset, and later re-enters the
/// inner header. `Region::While` has only the header's distinguished exit, so
/// absorbing that latch exit into the body drops the intervening outer-loop
/// blocks. Preserve the labelled CFG until the region algebra can express an
/// owned `break` followed by outer-loop work.
///
/// The terminal-header-exit restriction is load-bearing. Ordinary nested loops
/// also leave an inner cycle and later re-enter it through an outer latch, but
/// their header exit is the non-terminal continuation after the inner loop. They
/// remain representable by the existing nested-loop path and must not force a
/// whole-function fallback.
pub(super) fn has_inner_loop_exit_that_reenters_via_outer_cycle(cfg: &Cfg) -> bool {
    for header in 0..cfg.succs.len() {
        if cfg.dominating_tails(header).is_empty() {
            continue;
        }
        let body = cfg.natural_loop_body_of(header);
        let header_exits: HashSet<usize> = cfg.succs[header]
            .iter()
            .copied()
            .filter(|succ| !body.contains(succ))
            .collect();
        if header_exits.len() != 1 || !header_exits.iter().all(|&exit| cfg.succs[exit].is_empty()) {
            continue;
        }

        for block in body.iter().copied().filter(|&block| block != header) {
            for exit in cfg.succs[block]
                .iter()
                .copied()
                .filter(|succ| !body.contains(succ))
            {
                if !header_exits.contains(&exit) && can_reach(exit, header, cfg) {
                    return true;
                }
            }
        }
    }
    false
}

pub(super) fn has_multi_latch_loop_with_distinct_exits(cfg: &Cfg) -> bool {
    for header in 0..cfg.succs.len() {
        if cfg.dominating_tails(header).len() < 2 {
            continue;
        }
        let body = cfg.natural_loop_body_of(header);
        let header_exits: HashSet<usize> = cfg.succs[header]
            .iter()
            .copied()
            .filter(|succ| !body.contains(succ))
            .collect();
        if header_exits.is_empty() {
            continue;
        }
        let non_header_exits: HashSet<usize> = body
            .iter()
            .copied()
            .filter(|&block| block != header)
            .flat_map(|block| cfg.succs[block].iter().copied())
            .filter(|succ| !body.contains(succ))
            .collect();
        if non_header_exits
            .iter()
            .any(|exit| !header_exits.contains(exit))
        {
            return true;
        }
    }
    false
}

/// A conditional inside a natural loop may return through the same epilogue as
/// the loop's ordinary exit while its sibling continues to a latch.  The shared
/// epilogue post-dominates the conditional globally, but it is not a join owned
/// by that conditional *inside this iteration*.  `detect_if_shape` cannot encode
/// the split ownership yet, so recognise the unsafe case before it can invent an
/// edge from the continuing arm to the epilogue.
pub(super) fn has_loop_conditional_with_join_beyond_loop(cfg: &Cfg) -> bool {
    // A recovered multi-way dispatch already has a more precise Switch region.
    // Falling the *whole function* back would discard that information and can
    // expose raw indirect jumps, so leave those functions on the switch path.
    if cfg.succs.iter().any(|succs| succs.len() >= 3) {
        return false;
    }
    for header in 0..cfg.succs.len() {
        if cfg.dominating_tails(header).is_empty() {
            continue;
        }
        let body = cfg.natural_loop_body_of(header);

        for cond in body.iter().copied().filter(|&block| block != header) {
            if cfg.succs[cond].len() != 2 {
                continue;
            }
            // A direct edge to the loop header's own distinguished exit is a
            // source-level `break`, not an epilogue join owned by this body
            // conditional. The builder has a dedicated lossless shape for it.
            if loop_break_shape(cond, header, cfg).is_some() {
                continue;
            }
            let Some(join) = cfg.ipostdom[cond] else {
                continue;
            };
            if body.contains(&join) || join == header {
                continue;
            }
            let reaches_next_iteration = cfg.succs[cond]
                .iter()
                // A direct edge to the header is the ordinary loop latch.  Its
                // sibling may set final carried values on the way to the exit
                // (`while_prefix`); raw fallback before phi lowering loses those
                // values.  The ownership bug is an *internal* early-return
                // conditional whose continuing arm still has body work before
                // reaching a latch.
                .filter(|&&succ| succ != header && can_reach(succ, header, cfg))
                .count();
            let reaches_nonlocal_join = cfg.succs[cond]
                .iter()
                .filter(|&&succ| {
                    succ != join && !can_reach(succ, header, cfg) && can_reach(succ, join, cfg)
                })
                .count();
            if reaches_next_iteration > 0 && reaches_nonlocal_join > 0 {
                return true;
            }
        }
    }
    false
}
