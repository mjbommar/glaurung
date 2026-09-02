//! Loop shape detection: the four natural-loop recognisers and the block-set
//! walk they share.
//!
//! Each detector answers one question about a candidate header and, when it
//! commits, returns a [`LoopRegion`] — the structured region plus the single
//! block the parent's `build` should continue from.
//! [`detect_raw_dispatch_loop`] and [`detect_raw_multi_latch_loop`] own a
//! proven loop body as labelled CFG when no binary header condition exists;
//! [`detect_natural_loop`] and [`detect_bottom_tested_loop`] recover `While`
//! and `DoWhile`. [`loop_break_shape`] is the fifth recogniser and the odd one
//! out: it hands back the three blocks of a `break` rather than a region,
//! because both `super::build` and the fallback policy ask about it.
//!
//! The block-set walk they all share, [`natural_loop_body`], lives in
//! [`super::cfg`] with the memo it reads.
//!
//! [`natural_loop_body`]: super::cfg::natural_loop_body

use std::collections::HashSet;

use super::build;
use super::cfg::{natural_loop_body, Cfg};
use super::path_predicates::can_reach;
use super::region::Region;

pub(super) struct LoopRegion {
    pub(super) region: Region,
    pub(super) exit: Option<usize>,
}

/// Whether `header` owns a reducible natural loop containing one typed dispatch.
///
/// This is deliberately broader than [`detect_raw_dispatch_loop`]. A one-exit
/// dispatch loop can remain an ordinary `DoWhile` containing a `Switch`, so it
/// should not become a raw labelled loop. It must still suppress the
/// function-wide distinct-exit fallback long enough for that ordinary builder
/// to run.
pub(super) fn has_dispatch_natural_loop(header: usize, cfg: &Cfg) -> bool {
    dispatch_natural_loop_parts(header, cfg).is_some()
}

fn dispatch_natural_loop_parts(header: usize, cfg: &Cfg) -> Option<(HashSet<usize>, Vec<usize>)> {
    let tails: Vec<usize> = cfg.preds[header]
        .iter()
        .copied()
        .filter(|&tail| cfg.dominates(header, tail))
        .collect();
    if tails.is_empty() {
        return None;
    }

    let mut body = HashSet::new();
    for tail in tails {
        body.extend(natural_loop_body(header, tail, cfg).iter().copied());
    }
    if body
        .iter()
        .any(|&block| block != header && !cfg.dominates(header, block))
    {
        return None;
    }

    let dispatch_count = body
        .iter()
        .copied()
        .filter(|block| cfg.is_explicit_switch_dispatch(*block))
        .count();
    if dispatch_count != 1 {
        return None;
    }
    let mut exits: Vec<usize> = body
        .iter()
        .copied()
        .flat_map(|block| cfg.succs[block].iter().copied())
        .filter(|successor| !body.contains(successor))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    exits.sort_unstable();
    Some((body, exits))
}

/// Recognise a natural loop that contains exactly one resolved indirect dispatch.
///
/// A state-machine loop has no binary header condition that can be represented
/// as `While`: the table cases either update state and return to the dispatch,
/// or leave through one of several terminal paths. The ordinary switch builder
/// treats the dispatch as a one-shot choice and strands its back-edge. Own the
/// dominator-proven natural-loop body as labelled CFG instead. Every transfer
/// remains explicit during AST lowering, including all dispatch cases and all
/// exits.
pub(super) fn detect_raw_dispatch_loop(
    header: usize,
    cfg: &Cfg,
    visited: &mut HashSet<usize>,
) -> Option<LoopRegion> {
    let (body, exits) = dispatch_natural_loop_parts(header, cfg)?;
    // One normal-exhaustion path plus one terminal case is representable by
    // the ordinary structured loop/switch builder. Raw labelled CFG is needed
    // only once the dispatch has additional distinct exits that the current
    // region algebra cannot own without dropping or inventing an edge.
    if exits.len() < 3 {
        return None;
    }

    let mut blocks: Vec<usize> = body.into_iter().filter(|block| *block != header).collect();
    blocks.sort_unstable();
    blocks.insert(0, header);
    visited.extend(blocks.iter().copied());

    // Only a unique exit can be emitted immediately after the loop. Multiple
    // exits remain function-level labelled regions and are reached by the
    // explicit transfers emitted from RawLoop.
    let continuation = match exits.as_slice() {
        [exit] => Some(*exit),
        _ => None,
    };
    Some(LoopRegion {
        region: Region::RawLoop {
            header,
            blocks,
            exits,
        },
        exit: continuation,
    })
}

/// Recognise a reducible multi-latch loop whose only exits all reach the same
/// block and whose header has no exit edge of its own.
///
/// Both header successors remaining in the body means the header conditional is
/// an internal dispatch, not a loop test. Choosing either latch for `While` or
/// `DoWhile` would drop the other back-edge. The raw-loop region retains every
/// block and transfer once while still owning the natural-loop boundary.
pub(super) fn detect_raw_multi_latch_loop(
    header: usize,
    cfg: &Cfg,
    visited: &mut HashSet<usize>,
) -> Option<LoopRegion> {
    let tails: Vec<usize> = cfg.preds[header]
        .iter()
        .copied()
        .filter(|&tail| cfg.dominates(header, tail))
        .collect();
    if tails.len() < 2 {
        return None;
    }

    let mut body = HashSet::new();
    for tail in tails {
        body.extend(natural_loop_body(header, tail, cfg).iter().copied());
    }
    if cfg.succs[header].is_empty()
        || cfg.succs[header].iter().any(|succ| !body.contains(succ))
        || body
            .iter()
            .any(|&block| block != header && !cfg.dominates(header, block))
    {
        return None;
    }

    let exits: HashSet<usize> = body
        .iter()
        .copied()
        .flat_map(|block| cfg.succs[block].iter().copied())
        .filter(|successor| !body.contains(successor))
        .collect();
    let mut exits: Vec<usize> = exits.into_iter().collect();
    exits.sort_unstable();
    let [exit] = exits.as_slice() else {
        return None;
    };
    let exit = *exit;

    let mut blocks: Vec<usize> = body.into_iter().filter(|block| *block != header).collect();
    blocks.sort_unstable();
    blocks.insert(0, header);
    visited.extend(blocks.iter().copied());
    Some(LoopRegion {
        region: Region::RawLoop {
            header,
            blocks,
            exits,
        },
        exit: Some(exit),
    })
}

/// Recognise a natural while-loop headed at `header`.
///
/// The pattern:
///   * `header` has exactly two successors: `body_head` and `exit_block`.
///   * `body_head` eventually reaches back to `header` via a block `back` whose
///     only successor is `header` (single back-edge).
///   * `header` dominates `body_head` and `back`.
pub(super) fn detect_natural_loop(
    header: usize,
    cfg: &Cfg,
    visited: &mut HashSet<usize>,
) -> Option<LoopRegion> {
    if cfg.succs[header].len() != 2 {
        return None;
    }
    // A natural loop requires a back-edge: a predecessor `tail` of `header`
    // that `header` dominates.
    let tail = cfg.preds[header]
        .iter()
        .copied()
        .find(|&p| cfg.dominates(header, p))?;
    // The loop body is `header` plus every block that can reach `tail` without
    // passing back through `header` (the standard natural-loop body set).
    let body_set = natural_loop_body(header, tail, cfg);
    // Of the header's two successors, exactly one should be inside the body
    // (the loop entry); the other leaves the loop.
    let a = cfg.succs[header][0];
    let b = cfg.succs[header][1];
    let (body_head, exit) = match (body_set.contains(&a), body_set.contains(&b)) {
        (true, false) => (a, b),
        (false, true) => (b, a),
        // Both or neither inside → shape we don't model; fall back gracefully.
        _ => return None,
    };

    // Commit. Consume the header, then structure the body *recursively* via
    // `build` so nested loops and conditionals inside the body are recovered
    // too — the old linear walk bailed on any branch, leaving multi-level loops
    // (matrix multiply, nested sorts) as goto soup. Temporarily mark the exit
    // visited so body structuring can't escape the loop through it.
    visited.insert(header);
    let exit_was_visited = visited.contains(&exit);
    visited.insert(exit);
    let body = build(body_head, cfg, visited, Some(header));
    if !exit_was_visited {
        visited.remove(&exit);
    }
    Some(LoopRegion {
        region: Region::While {
            header,
            body: Box::new(body),
            exit: Some(exit),
        },
        exit: Some(exit),
    })
}

/// Recognise a natural loop whose conditional branch is in the latch.
///
/// The shape is `header ... -> cond`, with `cond -> header` as the back-edge and
/// `cond -> exit` leaving the loop. Unlike [`detect_natural_loop`], the loop
/// header need not branch: it is ordinary body code and therefore executes once
/// before the first condition test.
pub(super) fn detect_bottom_tested_loop(
    header: usize,
    cfg: &Cfg,
    visited: &mut HashSet<usize>,
) -> Option<LoopRegion> {
    // A genuine single-latch do-while has exactly one dominated predecessor of
    // its header. A pre-tested loop with `continue` or an early-exit arm may
    // also have a conditional predecessor that points to the header, but it has
    // at least one additional back-edge; accepting one predecessor out of that
    // set moves the first condition test after the body and changes behaviour.
    let mut back_preds = cfg.preds[header]
        .iter()
        .copied()
        .filter(|&candidate| cfg.dominates(header, candidate));
    let cond = back_preds.next()?;
    if back_preds.next().is_some()
        || cfg.succs[cond].len() != 2
        || !cfg.succs[cond].contains(&header)
        || cfg.cond_taken[cond].is_none()
        || visited.contains(&cond)
    {
        return None;
    }
    let body_set = natural_loop_body(header, cond, cfg);
    // Loop rotation puts an initial top-test in a predecessor outside the
    // natural loop, then uses a bottom latch for subsequent iterations. It is
    // a source-level do-while only *after* that zero-iteration test has been
    // retained as an explicit guard in the preceding region. `visited` proves
    // both the conditional and its non-loop sibling were already emitted; the
    // sibling's inability to re-enter proves it is the bypass path rather than
    // another loop entry. This admits `if (empty) return; do { ... } while
    // (more)` without admitting a bare rotated latch whose initial test could
    // otherwise be skipped.
    let outside_entries: Vec<usize> = cfg.preds[header]
        .iter()
        .copied()
        .filter(|pred| !body_set.contains(pred))
        .collect();
    let entries_are_unconditional = outside_entries
        .iter()
        .all(|&pred| cfg.succs[pred].len() == 1 && cfg.succs[pred][0] == header);
    let entry_guard_is_owned = if let [pred] = outside_entries.as_slice() {
        let bypasses: Vec<usize> = cfg.succs[*pred]
            .iter()
            .copied()
            .filter(|&successor| successor != header)
            .collect();
        matches!(bypasses.as_slice(), [bypass]
            if visited.contains(pred)
                && terminal_path_stays_outside_loop(*bypass, &body_set, cfg))
    } else {
        false
    };
    if !entries_are_unconditional && !entry_guard_is_owned {
        return None;
    }
    // A general second exit from the body still needs nested break/return
    // ownership that this bounded detector does not model.  A proven switch
    // arm is narrower: switch recovery already builds terminal arms with
    // borrowed epilogue ownership, so an acyclic arm that returns without
    // re-entering the loop can remain inside the DoWhile safely.
    let side_exits: Vec<(usize, usize)> = body_set
        .iter()
        .copied()
        .filter(|block| *block != cond)
        .flat_map(|block| {
            cfg.succs[block]
                .iter()
                .copied()
                .filter(|successor| !body_set.contains(successor))
                .map(move |successor| (block, successor))
        })
        .collect();
    if side_exits.iter().any(|(block, successor)| {
        !cfg.is_switch_dispatch(*block)
            || !terminal_path_stays_outside_loop(*successor, &body_set, cfg)
    }) {
        return None;
    }
    let exit = cfg.succs[cond]
        .iter()
        .copied()
        .find(|succ| *succ != header && !body_set.contains(succ))?;

    // The latch's condition belongs to the DoWhile node, not its body. Mark it
    // consumed while recursively structuring everything from the header up to
    // the latch. Temporarily consume the exit as well so an inner detector
    // cannot absorb control outside the loop.
    visited.insert(cond);
    let exit_was_visited = !visited.insert(exit);
    let body = build(header, cfg, visited, Some(cond));
    if !exit_was_visited {
        visited.remove(&exit);
    }

    Some(LoopRegion {
        region: Region::DoWhile {
            body: Box::new(body),
            cond,
            exit: Some(exit),
        },
        exit: Some(exit),
    })
}

/// Prove that a switch's loop-exiting arm is a finite return path.
///
/// Sharing the final return block with the loop's ordinary exit is allowed;
/// entering any loop block, cycling outside it, or ending without an explicit
/// machine return is not.  This is the ownership proof used by the narrow
/// bottom-tested-loop switch exception above.
pub(super) fn terminal_path_stays_outside_loop(
    start: usize,
    loop_body: &HashSet<usize>,
    cfg: &Cfg,
) -> bool {
    fn visit(
        block: usize,
        loop_body: &HashSet<usize>,
        cfg: &Cfg,
        visiting: &mut HashSet<usize>,
        proven: &mut HashSet<usize>,
    ) -> bool {
        if loop_body.contains(&block) {
            return false;
        }
        if proven.contains(&block) {
            return true;
        }
        if !visiting.insert(block) {
            return false;
        }
        let valid = if cfg.succs[block].is_empty() {
            cfg.ends_in_return[block]
        } else {
            cfg.succs[block]
                .iter()
                .copied()
                .all(|successor| visit(successor, loop_body, cfg, visiting, proven))
        };
        visiting.remove(&block);
        if valid {
            proven.insert(block);
        }
        valid
    }

    visit(
        start,
        loop_body,
        cfg,
        &mut HashSet::new(),
        &mut HashSet::new(),
    )
}

/// A conditional inside the natural loop headed at `header` whose one edge
/// reaches that loop's ordinary exit through an optional linear bridge and
/// whose sibling continues to a latch.
///
/// The bridge is retained in the returned region, so result setup on a
/// break/early-return path is not discarded or moved after the loop.
pub(super) fn loop_break_shape(
    cond: usize,
    header: usize,
    cfg: &Cfg,
) -> Option<(usize, usize, usize, bool)> {
    if cfg.succs.get(cond)?.len() != 2 || cfg.succs.get(header)?.len() != 2 {
        return None;
    }
    if cfg.dominating_tails(header).is_empty() {
        return None;
    }
    let body = cfg.natural_loop_body_of(header);
    let header_exits: Vec<usize> = cfg.succs[header]
        .iter()
        .copied()
        .filter(|successor| !body.contains(successor))
        .collect();
    let [exit] = header_exits.as_slice() else {
        return None;
    };
    let exit = *exit;
    for break_entry in cfg.succs[cond].iter().copied() {
        let continuation = cfg.succs[cond]
            .iter()
            .copied()
            .find(|&successor| successor != break_entry)?;
        if !body.contains(&continuation) || !can_reach(continuation, header, cfg) {
            continue;
        }
        if break_entry != exit {
            let mut current = break_entry;
            let mut seen = HashSet::new();
            while current != exit && seen.insert(current) {
                if body.contains(&current)
                    || !cfg.dominates(cond, current)
                    || cfg.succs[current].len() != 1
                {
                    break;
                }
                current = cfg.succs[current][0];
            }
            if current != exit {
                continue;
            }
        }
        let taken = cfg.cond_taken[cond]?;
        return Some((exit, continuation, break_entry, taken != break_entry));
    }
    None
}
