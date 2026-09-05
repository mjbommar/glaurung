//! Path predicates over the CFG: the reachability proofs the shape detectors
//! ask before they commit to a structured region.
//!
//! Every item here is a pure question about [`super::cfg::Cfg`] — nothing is built
//! and no block ownership is claimed. They are the "may I?" half of
//! structuring. [`every_path_reaches_join`] and
//! [`every_path_reaches_join_or_terminates`] decide whether a diamond really
//! closes; [`cyclic_body_exits_only_to_join`] is the one deliberate cyclic
//! exception to the first of those. [`shared_return_chain`] bounds which tails
//! a borrowed return view may render. [`can_reach`] and
//! [`contains_multiway_before`] are the raw walks
//! the rest are built from.

use std::collections::{HashMap, HashSet};

use super::cfg::Cfg;

/// Return the exact acyclic block chain from a shared entry through a machine
/// return.  Interior blocks must be private to the chain; only its terminal may
/// merge other return-value paths.  This deliberately refuses calls without an
/// explicit return, branches, cycles, and long chains so duplicating it cannot
/// invent source-level termination or cause pathological AST growth.
pub(super) fn shared_return_chain(entry: usize, cfg: &Cfg) -> Option<Vec<usize>> {
    if cfg.preds[entry].len() <= 1 {
        return None;
    }

    let mut chain = Vec::new();
    let mut seen = HashSet::new();
    let mut current = entry;
    for _ in 0..8 {
        if !seen.insert(current) {
            return None;
        }
        chain.push(current);
        match cfg.succs[current].as_slice() {
            [] if cfg.ends_in_return[current] => return Some(chain),
            [next] => {
                if cfg.preds[*next].iter().any(|pred| !seen.contains(pred))
                    && !cfg.ends_in_return[*next]
                {
                    return None;
                }
                current = *next;
            }
            _ => return None,
        }
    }
    None
}

/// True when every path starting at `start` either reaches `join` or ends at a
/// terminal block. Cycles encountered before the join are rejected
/// conservatively: the optional-preheader rule is for acyclic one-time setup,
/// not for guessing ownership of another loop.
pub(super) fn every_path_reaches_join_or_terminates(start: usize, join: usize, cfg: &Cfg) -> bool {
    fn visit(
        node: usize,
        join: usize,
        cfg: &Cfg,
        active: &mut HashSet<usize>,
        memo: &mut HashMap<usize, bool>,
    ) -> bool {
        if node == join || cfg.succs[node].is_empty() {
            return true;
        }
        if let Some(&known) = memo.get(&node) {
            return known;
        }
        if !active.insert(node) {
            return false;
        }
        let valid = cfg.succs[node]
            .iter()
            .copied()
            .all(|succ| visit(succ, join, cfg, active, memo));
        active.remove(&node);
        memo.insert(node, valid);
        valid
    }

    visit(start, join, cfg, &mut HashSet::new(), &mut HashMap::new())
}

/// True when every path from `start` reaches `join`, with no alternate terminal
/// and no cycle before the join. This stronger predicate is required when one
/// conditional successor is the join itself: accepting an unrelated terminal
/// would misclassify short-circuit boolean graphs as one-armed conditionals.
pub(super) fn every_path_reaches_join(start: usize, join: usize, cfg: &Cfg) -> bool {
    fn visit(
        node: usize,
        join: usize,
        cfg: &Cfg,
        active: &mut HashSet<usize>,
        memo: &mut HashMap<usize, bool>,
    ) -> bool {
        if node == join {
            return true;
        }
        if cfg.succs[node].is_empty() {
            return false;
        }
        if let Some(&known) = memo.get(&node) {
            return known;
        }
        if !active.insert(node) {
            return false;
        }
        let valid = cfg.succs[node]
            .iter()
            .copied()
            .all(|succ| visit(succ, join, cfg, active, memo));
        active.remove(&node);
        memo.insert(node, valid);
        valid
    }

    visit(start, join, cfg, &mut HashSet::new(), &mut HashMap::new())
}

/// Prove a cyclic one-armed conditional whose loop exits only through `join`.
///
/// The ordinary [`every_path_reaches_join`] proof rejects every cycle. That is
/// right for acyclic setup arms but too strong for `if (n != 0) { for (...) }
/// when the compiler rotates the nested loop: every loop node can still reach
/// the direct sibling join, and there is no terminal or edge back through the
/// owning condition. Requiring an actual typed back-edge keeps this exception
/// specific to cyclic arms rather than weakening the ordinary diamond rule.
pub(super) fn cyclic_body_exits_only_to_join(
    start: usize,
    join: usize,
    owner: usize,
    cfg: &Cfg,
) -> bool {
    let mut reachable = HashSet::new();
    let mut stack = vec![start];
    while let Some(block) = stack.pop() {
        if block == join {
            continue;
        }
        if block == owner || !reachable.insert(block) {
            if block == owner {
                return false;
            }
            continue;
        }
        if cfg.succs[block].is_empty() {
            return false;
        }
        stack.extend(cfg.succs[block].iter().copied());
    }
    let has_back_edge = reachable.iter().copied().any(|block| {
        cfg.edges[block]
            .iter()
            .any(|edge| edge.back && reachable.contains(&edge.to))
    });
    has_back_edge
        && reachable
            .iter()
            .copied()
            .all(|block| can_reach(block, join, cfg))
}

/// Whether `target` is reachable from `start` along successor edges, `start`
/// included (`can_reach(b, b)` is true).
///
/// This was a fresh depth-first search, with a fresh `HashSet`, per call. It is
/// the innermost question the loop-shape predicates ask — once per (header,
/// body conditional, successor) triple — and its answer is fixed for the life
/// of the `Cfg`, so it now reads a bit out of the closure `Cfg` builds on first
/// use. Same relation, same reflexive convention; only the number of times it
/// is computed changed.
pub(super) fn can_reach(start: usize, target: usize, cfg: &Cfg) -> bool {
    cfg.can_reach(start, target)
}

pub(super) fn contains_multiway_before(start: usize, boundary: usize, cfg: &Cfg) -> bool {
    let mut seen = HashSet::new();
    let mut stack = vec![start];
    while let Some(block) = stack.pop() {
        if block == boundary || !seen.insert(block) {
            continue;
        }
        if cfg.succs[block].len() >= 3 {
            return true;
        }
        stack.extend(cfg.succs[block].iter().copied());
    }
    false
}
