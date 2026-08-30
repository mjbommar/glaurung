//! Switch recovery: the dispatch and guarded-dispatch shapes, arm ownership,
//! and the join search the two share.
//!
//! Two entry points reach here from [`super::build`].
//! [`detect_switch_shape`] folds a bare N-way dispatch;
//! [`detect_guarded_switch_shape`] folds an unsigned range check together with
//! the indirect dispatch it guards into a single region carrying a formal
//! default.
//!
//! Everything else is ownership bookkeeping for those two. A switch nested in
//! a natural loop is the hard case throughout: a case can leave through a
//! block the loop's ordinary exit also uses, so
//! [`innermost_natural_loop_containing`] bounds the join search in
//! [`find_switch_join_from`], and [`commit_borrowed_switch_arm`] decides which
//! of an arm's visited blocks may be claimed globally.
//! [`switch_arm_build_order`] orders the arms so that case-to-case fallthrough
//! renders as an explicit `Goto` rather than an invented `break`.

use std::collections::{HashMap, HashSet};

use super::path_predicates::can_reach;
use super::{build, natural_loop_body, Cfg, Region};

/// Commit the blocks a switch arm uniquely owns while leaving a shared tail
/// available to the enclosing region.
///
/// A switch arm inside a natural loop can leave through a case-local block and
/// then enter the same epilogue as the loop's ordinary exit. The dispatch
/// dominates the case-local path, but not that shared epilogue, so dominance is
/// the ownership boundary missing from a loop-membership-only filter.
fn commit_borrowed_switch_arm(
    dispatch: usize,
    loop_body: &HashSet<usize>,
    cfg: &Cfg,
    borrowed: HashSet<usize>,
    visited: &mut HashSet<usize>,
) {
    visited.extend(
        borrowed
            .into_iter()
            .filter(|&block| loop_body.contains(&block) || cfg.dominates(dispatch, block)),
    );
}

/// Recognise a switch dispatch (#193).
///
/// Pattern: `cur` has N>=3 successors. Each arm should have `cur` as
/// either its only predecessor (clean dispatch) or as one of a small
/// number of preds when other arms fall through. We identify a join
/// block as the multi-predecessor block reached from the greatest number of
/// distinct arms. Counting distinct arms matters: a merge wholly inside one case
/// or a shared exceptional exit used by only two cases is not the normal switch
/// continuation when more cases converge elsewhere.
///
/// Each arm is then recursively built with `stop_at = join`. Arms
/// that terminate without reaching the join become Region sub-trees
/// with their own returns.
pub(super) fn detect_switch_shape(
    dispatch: usize,
    cfg: &Cfg,
    visited: &mut HashSet<usize>,
    enclosing_stop: Option<usize>,
) -> Option<(Region, Option<usize>)> {
    let all_arms = cfg.succs[dispatch].clone();
    let mut arms = all_arms.clone();
    let mut case_labels = cfg.case_labels[dispatch].clone();
    if arms.len() < 2 || !cfg.is_switch_dispatch(dispatch) {
        return None;
    }
    let formal_default_entry = arms
        .iter()
        .position(|arm| is_guarded_switch_default(dispatch, *arm, cfg))
        .map(|position| {
            case_labels.remove(position);
            arms.remove(position)
        });
    if arms.is_empty() {
        return None;
    }
    let join = find_switch_join(dispatch, &all_arms, cfg, enclosing_stop);
    // When the dispatch is one arm of an enclosing conditional, its local
    // post-dominator may be absent solely because the sibling/default arm also
    // reaches that continuation.  The enclosing boundary is still a proven
    // join and is the correct ownership limit for every case.
    let effective_join = join.or(enclosing_stop);
    let arm_build_order = switch_arm_build_order(dispatch, &arms, cfg, effective_join)?;
    let enclosing_loop = innermost_natural_loop_containing(dispatch, cfg);

    visited.insert(dispatch);
    let mut sub_arms: Vec<Option<Region>> = vec![None; arms.len()];
    // A switch may have no join dominated by its dispatch while still being
    // nested inside a region with a shared continuation.  The canonical shape
    // is an out-of-range guard whose direct/default arm and every switch case
    // meet at the same epilogue.  In that case `join` is None (the default path
    // prevents dispatch dominance), but `enclosing_stop` is authoritative: no
    // case owns or may consume that outer continuation.
    let arm_stop = effective_join;
    for arm_index in arm_build_order {
        let a = arms[arm_index];
        let arm = if let Some((_, loop_body)) = &enclosing_loop {
            // Case-local returns may pass through a function epilogue outside
            // the loop. Render that path in the case, but do not globally claim
            // the shared epilogue: the loop-exit and pre-loop paths still need
            // it at function scope. Case-local blocks dominated by the
            // dispatch are uniquely owned even when they sit outside the
            // natural-loop body.
            let mut arm_visited = visited.clone();
            let arm = build(a, cfg, &mut arm_visited, arm_stop);
            commit_borrowed_switch_arm(dispatch, loop_body, cfg, arm_visited, visited);
            arm
        } else {
            build(a, cfg, visited, arm_stop)
        };
        sub_arms[arm_index] = Some(arm);
    }
    let sub_arms = sub_arms
        .into_iter()
        .map(|arm| arm.expect("every validated switch arm has a build order"))
        .collect();
    let formal_default = formal_default_entry.map(|entry| {
        let mut borrowed_visited = HashSet::from([dispatch]);
        Box::new(build(entry, cfg, &mut borrowed_visited, arm_stop))
    });
    Some((
        Region::Switch {
            guard: None,
            dispatch,
            case_labels,
            arms: sub_arms,
            formal_default,
            join: effective_join,
        },
        effective_join,
    ))
}

/// Fold an unsigned range guard and its resolved indirect dispatch into one
/// switch region. The guard's other edge is the formal default, including when
/// jump-table holes also target it. A case target may itself be the shared exit
/// reached by the default; that case becomes an empty body followed by the
/// switch's ordinary continuation.
pub(super) fn detect_guarded_switch_shape(
    guard: usize,
    cfg: &Cfg,
    visited: &mut HashSet<usize>,
    enclosing_stop: Option<usize>,
) -> Option<(Region, Option<usize>)> {
    let [first, second] = cfg.succs[guard].as_slice() else {
        return None;
    };
    let (dispatch, default_entry) =
        [(*first, *second), (*second, *first)]
            .into_iter()
            .find(|(dispatch, default_entry)| {
                cfg.is_switch_dispatch(*dispatch)
                    && cfg.preds[*dispatch] == vec![guard]
                    && is_guarded_switch_default(*dispatch, *default_entry, cfg)
            })?;

    let all_arms = cfg.succs[dispatch].clone();
    let mut arms = all_arms.clone();
    let mut case_labels = cfg.case_labels[dispatch].clone();
    let default_position = arms.iter().position(|arm| *arm == default_entry)?;
    arms.remove(default_position);
    case_labels.remove(default_position);
    if arms.is_empty() {
        return None;
    }

    let join = find_switch_join_from(
        guard,
        dispatch,
        &all_arms,
        cfg,
        enclosing_stop,
        Some(default_entry),
    )
    .or(enclosing_stop);
    let arm_build_order = switch_arm_build_order(dispatch, &arms, cfg, join)?;

    visited.insert(dispatch);
    let enclosing_loop = innermost_natural_loop_containing(dispatch, cfg);
    let mut sub_arms: Vec<Option<Region>> = vec![None; arms.len()];
    for arm_index in arm_build_order {
        let arm = arms[arm_index];
        let region = if Some(arm) == join {
            // Direct dispatch-to-join is `case ...: break;`. The join is emitted
            // once after the switch instead of being duplicated in the case.
            Region::Seq(Vec::new())
        } else if let Some((_, loop_body)) = &enclosing_loop {
            let mut arm_visited = visited.clone();
            let region = build(arm, cfg, &mut arm_visited, join);
            commit_borrowed_switch_arm(dispatch, loop_body, cfg, arm_visited, visited);
            region
        } else {
            build(arm, cfg, visited, join)
        };
        sub_arms[arm_index] = Some(region);
    }
    let sub_arms = sub_arms
        .into_iter()
        .map(|arm| arm.expect("every validated guarded switch arm has a build order"))
        .collect();
    // The default target is allowed to be a shared suffix reached from case
    // bodies (and from jump-table holes).  Case recovery therefore may visit it
    // before this branch is materialised.  Build the formal default against a
    // borrowed ownership set, just as the unguarded-switch path above does:
    // region ownership is not the same thing as CFG reachability, and cloning a
    // shared suffix is preferable to dropping the guard's executable edge.
    let mut default_visited = HashSet::from([guard, dispatch]);
    let formal_default = Box::new(build(default_entry, cfg, &mut default_visited, join));

    Some((
        Region::Switch {
            guard: Some(guard),
            dispatch,
            case_labels,
            arms: sub_arms,
            formal_default: Some(formal_default),
            join,
        },
        join,
    ))
}

/// Validate switch-arm ownership and return the order in which arm regions must
/// be built. Case-to-case edges are source-level fallthrough. Building their
/// destinations first leaves each source with an explicit `Goto` to the label
/// owned by the later case, which is lossless with the existing region algebra
/// and prevents the renderer from inventing an implicit `break`.
fn switch_arm_build_order(
    dispatch: usize,
    arms: &[usize],
    cfg: &Cfg,
    shared_join: Option<usize>,
) -> Option<Vec<usize>> {
    use std::collections::VecDeque;

    let positions: HashMap<usize, usize> = arms
        .iter()
        .copied()
        .enumerate()
        .map(|(position, arm)| (arm, position))
        .collect();
    if arms.iter().any(|arm| {
        Some(*arm) != shared_join
            && cfg.preds[*arm]
                .iter()
                .any(|pred| *pred != dispatch && !positions.contains_key(pred))
    }) {
        return None;
    }

    let mut indegree = vec![0usize; arms.len()];
    for &arm in arms {
        for successor in cfg.succs[arm]
            .iter()
            .filter_map(|successor| positions.get(successor).copied())
        {
            indegree[successor] += 1;
        }
    }
    let mut queue: VecDeque<usize> = indegree
        .iter()
        .enumerate()
        .filter_map(|(position, degree)| (*degree == 0).then_some(position))
        .collect();
    let mut topological = Vec::with_capacity(arms.len());
    while let Some(position) = queue.pop_front() {
        topological.push(position);
        for successor in cfg.succs[arms[position]]
            .iter()
            .filter_map(|successor| positions.get(successor).copied())
        {
            indegree[successor] -= 1;
            if indegree[successor] == 0 {
                queue.push_back(successor);
            }
        }
    }
    if topological.len() != arms.len() {
        return None;
    }
    topological.reverse();
    Some(topological)
}

/// Return true when `candidate` is both a table destination and the proven
/// out-of-range target of the conditional guarding `dispatch`.
fn is_guarded_switch_default(dispatch: usize, candidate: usize, cfg: &Cfg) -> bool {
    cfg.preds[candidate].iter().any(|guard| {
        cfg.edges[*guard].iter().any(|edge| {
            edge.to == candidate && edge.kind == crate::ir::cfg_edges::EdgeKind::SwitchDefault
        }) && cfg.edges[*guard].iter().any(|edge| edge.to == dispatch)
    })
}

/// Walk reachable blocks from each arm and return the block reached from the
/// greatest number of DISTINCT arms that also has >1 predecessors and is
/// dominated by `dispatch`. Address order breaks ties only after arm coverage;
/// otherwise an earlier shared error exit can steal the normal continuation.
/// None if no candidate is shared by at least two arms.
pub(super) fn find_switch_join(
    dispatch: usize,
    arms: &[usize],
    cfg: &Cfg,
    enclosing_stop: Option<usize>,
) -> Option<usize> {
    find_switch_join_from(dispatch, dispatch, arms, cfg, enclosing_stop, None)
}

fn find_switch_join_from(
    dominance_root: usize,
    dispatch: usize,
    arms: &[usize],
    cfg: &Cfg,
    enclosing_stop: Option<usize>,
    arm_join_source: Option<usize>,
) -> Option<usize> {
    use std::collections::VecDeque;
    let enclosing_loop = innermost_natural_loop_containing(dispatch, cfg);
    let mut arm_reach_counts: HashMap<usize, usize> = HashMap::new();
    for &a in arms {
        let mut q: VecDeque<usize> = VecDeque::new();
        q.push_back(a);
        let mut seen: HashSet<usize> = HashSet::new();
        while let Some(b) = q.pop_front() {
            // A switch nested in a loop must not walk through the loop header
            // into a later iteration. Doing so makes every case-internal merge
            // appear reachable from every arm and selects it as the join.
            if Some(b) == enclosing_stop {
                continue;
            }
            // A local if/else join can replace the loop header as `stop_at`
            // while recursively building a switch nested inside that arm. Find
            // the natural loop independently: paths leaving its body are case
            // exits, and the header starts the *next* iteration, neither of
            // which may participate in this iteration's switch join.
            if let Some((header, body)) = &enclosing_loop {
                if b == *header || !body.contains(&b) {
                    continue;
                }
            }
            if !seen.insert(b) {
                continue;
            }
            for &s in &cfg.succs[b] {
                if !seen.contains(&s) {
                    q.push_back(s);
                }
            }
        }
        for b in seen {
            *arm_reach_counts.entry(b).or_default() += 1;
        }
    }
    let mut candidates: Vec<(usize, usize)> = arm_reach_counts
        .into_iter()
        .filter_map(|(b, arm_count)| {
            (arm_count > 1
                && (!arms.contains(&b)
                    || arm_join_source
                        .is_some_and(|source| source != b && can_reach(source, b, cfg)))
                && cfg.preds[b].len() > 1
                && cfg.dominates(dominance_root, b))
            .then_some((arm_count, b))
        })
        .collect();
    candidates.sort_unstable_by(|(count_a, block_a), (count_b, block_b)| {
        count_b.cmp(count_a).then_with(|| block_a.cmp(block_b))
    });
    candidates.into_iter().next().map(|(_, block)| block)
}

/// The smallest natural-loop body containing `node`, paired with its header.
/// Smallest is the innermost loop when loops are nested. A header may have more
/// than one back-edge, so its body is the union of the standard predecessor
/// walks from every dominated tail.
fn innermost_natural_loop_containing(node: usize, cfg: &Cfg) -> Option<(usize, HashSet<usize>)> {
    let mut loops = Vec::new();
    for header in 0..cfg.succs.len() {
        if !cfg.dominates(header, node) {
            continue;
        }
        let tails: Vec<usize> = cfg.preds[header]
            .iter()
            .copied()
            .filter(|&tail| cfg.dominates(header, tail))
            .collect();
        if tails.is_empty() {
            continue;
        }
        let mut body = HashSet::new();
        for tail in tails {
            body.extend(natural_loop_body(header, tail, cfg).iter().copied());
        }
        if body.contains(&node) {
            loops.push((header, body));
        }
    }
    loops.into_iter().min_by_key(|(_, body)| body.len())
}
