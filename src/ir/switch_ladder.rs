//! Recover a `switch` from the comparison ladder gcc emits at `-O0`.
//!
//! A `switch` over a small dense range does not have to become a jump table. At
//! `-O0` gcc routinely emits a binary-search decision tree instead:
//!
//! ```text
//!     cmpl $0x7,-0x4(%rbp); je   case7
//!     cmpl $0x7,-0x4(%rbp); jg   default
//!     cmpl $0x6,-0x4(%rbp); je   case6
//!     cmpl $0x6,-0x4(%rbp); jg   default
//!     ...
//! ```
//!
//! Structuring that faithfully produces deeply nested `if`/`else` with one `goto`
//! per range-prune edge into the shared `default` arm. It is correct, and it is
//! nothing like the `switch` in the source: on the DecBench corpus the single
//! function `dispatch` scores a graph edit distance of 84 that way.
//!
//! There is no jump table here to recover — the machine really did compare — so
//! this works on the structured AST rather than the CFG. It matches a tree whose
//! every test is against ONE side-effect-free value, collects the `== constant`
//! arms as cases, treats the relational tests as range prunes that lead to the
//! default, and rewrites the whole tree as `Stmt::Switch`. The `goto`s and their
//! label disappear with it.
//!
//! Conservative by construction: anything that does not fit the shape exactly —
//! a second discriminant, a duplicate case constant, more than one distinct
//! default, a surviving `goto` into the label from outside the tree — leaves the
//! function untouched.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::{BinOp, CmpOp, VReg};

/// Fewer arms than this stay nested `if`/`else`. Two or three equality tests read
/// as what they are in the source, and are not what blows up the graph distance.
const MIN_CASES: usize = 4;

/// Rewrite every comparison ladder in `f` as a `switch`.
pub fn recover_switches(f: &mut Function) {
    recover_top_level_goto_switches(&mut f.body);
    rewrite_body(&mut f.body);
    // A label is only dropped once nothing references it any more.
    let live = goto_targets(&f.body);
    prune_labels(&mut f.body, &live);
}

/// Recover the other form produced when region structuring cannot nest GCC's
/// comparisons: a linear run of guarded gotos followed by labelled case bodies.
///
/// This is not a generic "labels look like cases" heuristic.  The dispatch must
/// prove the same range/equality partition as [`try_ladder`], every case label
/// must have exactly one incoming goto (the dispatch edge), and each carved case
/// body must end in an unconditional transfer.  Those conditions make moving
/// the bodies under a `Switch` control-flow preserving.
///
/// Only the function's top-level statement list is eligible. For a nested list,
/// an incoming goto may live in an enclosing list and would be invisible to the
/// exact-reference proof below; declining that shape is safer than guessing.
fn recover_top_level_goto_switches(body: &mut Vec<Stmt>) {
    while recover_one_goto_switch(body) {}
}

#[derive(Clone)]
struct GotoCase {
    value: i64,
    label: u64,
}

struct GotoDispatch {
    discriminant: VReg,
    end: usize,
    cases: Vec<GotoCase>,
    join: u64,
}

fn recover_one_goto_switch(body: &mut Vec<Stmt>) -> bool {
    for start in 0..body.len() {
        let Some(dispatch) = parse_goto_dispatch(body, start) else {
            continue;
        };
        let Some(join_position) = unique_label_position(body, dispatch.join) else {
            continue;
        };
        if join_position < dispatch.end {
            continue;
        }

        let mut positioned = Vec::with_capacity(dispatch.cases.len());
        let mut valid = true;
        for case in &dispatch.cases {
            let Some(position) = unique_label_position(body, case.label) else {
                valid = false;
                break;
            };
            if position < dispatch.end
                || position >= join_position
                || count_gotos_body(body, case.label) != 1
            {
                valid = false;
                break;
            }
            positioned.push((position, case.clone()));
        }
        if !valid {
            continue;
        }
        positioned.sort_by_key(|(position, _)| *position);
        if positioned.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            continue;
        }
        let Some((first_case_position, _)) = positioned.first() else {
            continue;
        };
        if body[dispatch.end..*first_case_position]
            .iter()
            .any(|statement| !matches!(statement, Stmt::Nop | Stmt::Comment(_)))
        {
            continue;
        }

        let mut cases = Vec::with_capacity(positioned.len());
        for (case_index, (position, case)) in positioned.iter().enumerate() {
            let next_position = positioned
                .get(case_index + 1)
                .map(|(next, _)| *next)
                .unwrap_or(join_position);
            let mut case_body = body[position + 1..next_position].to_vec();
            if !ends_in_unconditional_transfer(&case_body) {
                valid = false;
                break;
            }
            replace_join_gotos(&mut case_body, dispatch.join);
            drop_renderer_supplied_break(&mut case_body);
            cases.push((Some(case.value), case_body));
        }
        if !valid {
            continue;
        }
        // Source case order is the clearest stable spelling; dispatch-tree order
        // is an implementation detail of GCC's binary search.
        cases.sort_by_key(|(value, _)| *value);
        let switch = Stmt::Switch {
            discriminant: Expr::Reg(dispatch.discriminant),
            cases,
            default: None,
        };
        body.splice(start..join_position, std::iter::once(switch));
        return true;
    }
    false
}

fn parse_goto_dispatch(body: &[Stmt], start: usize) -> Option<GotoDispatch> {
    let mut discriminant = None;
    let mut cases = Vec::new();
    let mut join = None;
    let mut reachable = Range::full();
    let mut index = start;

    loop {
        match body.get(index)? {
            Stmt::If {
                cond,
                then_body,
                else_body: None,
            } => {
                let target = sole_goto(then_body)?;
                match classify(cond, &mut discriminant)? {
                    Test::Case(value) => {
                        if !reachable.contains(value)
                            || cases
                                .iter()
                                .any(|case: &GotoCase| case.value == value || case.label == target)
                        {
                            return None;
                        }
                        cases.push(GotoCase {
                            value,
                            label: target,
                        });
                    }
                    Test::Prune(bound) => {
                        if join.is_some_and(|seen| seen != target) {
                            return None;
                        }
                        join = Some(target);
                        reachable.narrow(&bound);
                    }
                }
                index += 1;
            }
            Stmt::Goto { target } => {
                if join.is_some_and(|seen| seen != *target) {
                    return None;
                }
                join = Some(*target);
                index += 1;
                break;
            }
            _ => return None,
        }
    }

    if cases.len() < MIN_CASES || cases.iter().any(|case| Some(case.label) == join) {
        return None;
    }
    Some(GotoDispatch {
        discriminant: discriminant?,
        end: index,
        cases,
        join: join?,
    })
}

fn unique_label_position(body: &[Stmt], target: u64) -> Option<usize> {
    let mut positions = body.iter().enumerate().filter_map(|(index, statement)| {
        matches!(statement, Stmt::Label(label) if *label == target).then_some(index)
    });
    let position = positions.next()?;
    positions.next().is_none().then_some(position)
}

fn count_gotos_body(body: &[Stmt], target: u64) -> usize {
    body.iter()
        .map(|statement| count_gotos_stmt(statement, target))
        .sum()
}

fn count_gotos_stmt(statement: &Stmt, target: u64) -> usize {
    match statement {
        Stmt::Goto { target: seen } => usize::from(*seen == target),
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            count_gotos_body(then_body, target)
                + else_body
                    .as_deref()
                    .map(|body| count_gotos_body(body, target))
                    .unwrap_or(0)
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
            count_gotos_body(body, target)
        }
        Stmt::Switch { cases, default, .. } => {
            cases
                .iter()
                .map(|(_, body)| count_gotos_body(body, target))
                .sum::<usize>()
                + default
                    .as_deref()
                    .map(|body| count_gotos_body(body, target))
                    .unwrap_or(0)
        }
        _ => 0,
    }
}

fn ends_in_unconditional_transfer(body: &[Stmt]) -> bool {
    body.iter()
        .rev()
        .find(|statement| !matches!(statement, Stmt::Nop | Stmt::Comment(_) | Stmt::Label(_)))
        .is_some_and(|statement| {
            matches!(
                statement,
                Stmt::Goto { .. } | Stmt::IndirectGoto { .. } | Stmt::Return { .. } | Stmt::Break
            )
        })
}

/// A join goto directly inside a case (possibly under an `if`) is the source
/// `break`. Do not descend through a nested loop/switch: there the same goto may
/// intentionally escape a different control construct and must remain explicit.
fn replace_join_gotos(body: &mut [Stmt], join: u64) {
    for statement in body {
        match statement {
            Stmt::Goto { target } if *target == join => *statement = Stmt::Break,
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                replace_join_gotos(then_body, join);
                if let Some(else_body) = else_body {
                    replace_join_gotos(else_body, join);
                }
            }
            _ => {}
        }
    }
}

/// The C renderer appends the ordinary case-ending `break` itself. Keep breaks
/// under an internal conditional, but remove the redundant terminal one created
/// from the case's unconditional join edge.
fn drop_renderer_supplied_break(body: &mut Vec<Stmt>) {
    let Some(position) = body
        .iter()
        .rposition(|statement| !matches!(statement, Stmt::Nop | Stmt::Comment(_)))
    else {
        return;
    };
    if matches!(body[position], Stmt::Break) {
        body.remove(position);
    }
}

/// Rewrite OUTSIDE-IN: try the widest ladder rooted at each statement before
/// looking inside it.
///
/// Inside-out is wrong here, and quietly so. Every suffix of a ladder is itself a
/// ladder, so recursing first lets the subtree below `case 7` match on its own —
/// producing a `switch` over cases 0..6 nested in an `if (v == 7)`, which is a
/// partial recovery that is worse than either whole answer. Matching the root
/// first takes the longest chain; the arms are then rewritten in turn, so a
/// genuinely nested ladder inside a case body is still found.
fn rewrite_body(body: &mut [Stmt]) {
    for s in body.iter_mut() {
        if let Some(sw) = try_ladder(s) {
            *s = sw;
        }
        rewrite_stmt(s);
    }
}

fn rewrite_stmt(s: &mut Stmt) {
    match s {
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            rewrite_body(then_body);
            if let Some(b) = else_body {
                rewrite_body(b);
            }
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => rewrite_body(body),
        Stmt::For {
            init, step, body, ..
        } => {
            rewrite_body(std::slice::from_mut(init.as_mut()));
            rewrite_body(body);
            rewrite_body(std::slice::from_mut(step.as_mut()));
        }
        Stmt::Switch { cases, default, .. } => {
            for (_, b) in cases.iter_mut() {
                rewrite_body(b);
            }
            if let Some(b) = default {
                rewrite_body(b);
            }
        }
        _ => {}
    }
}

/// What a single test in the ladder says about the discriminant.
enum Test {
    /// `v == c` — the `then` arm is case `c`.
    Case(i64),
    /// A relational test whose `then` arm is a route to the default. The payload
    /// is what taking the `else` arm proves about the discriminant: an inclusive
    /// bound that narrows the range still reachable further down the ladder.
    Prune(Bound),
}

/// What the `else` arm of a prune proves: the discriminant is at most, or at
/// least, this value.
enum Bound {
    AtMost(i64),
    AtLeast(i64),
}

/// The range of discriminant values still reachable at a point in the walk.
///
/// This is what makes the rewrite sound rather than merely plausible. A `switch`
/// dispatches on equality alone, so it is only equivalent to the tree if every
/// equality test the tree performs is actually REACHABLE for its constant. A tree
/// like `if (5 < v) default; else if (v == 7) A7` sends `v == 7` to the default,
/// while the switch would take `A7`. gcc's binary search never emits that, but
/// "the compiler would not do that" is not a soundness argument.
#[derive(Clone, Copy)]
struct Range {
    lo: i64,
    hi: i64,
}

impl Range {
    fn full() -> Self {
        Range {
            lo: i64::MIN,
            hi: i64::MAX,
        }
    }
    fn contains(&self, k: i64) -> bool {
        k >= self.lo && k <= self.hi
    }
    /// Narrow by what the `else` arm of a prune proved. Saturating: a bound at the
    /// extreme of the type cannot be stepped past, and an empty range simply stops
    /// containing anything.
    fn narrow(&mut self, b: &Bound) {
        match b {
            Bound::AtMost(c) => self.hi = self.hi.min(*c),
            Bound::AtLeast(c) => self.lo = self.lo.max(*c),
        }
    }
}

/// Classify a condition as a test on `disc`, binding `disc` on the first one.
///
/// Only the SIGNED relational forms are accepted. An unsigned prune would need the
/// range tracked in unsigned space, and mixing the two in one ladder is not a
/// shape we can reason about — better to leave those trees alone.
fn classify(cond: &Expr, disc: &mut Option<VReg>) -> Option<Test> {
    // x86 `jg` is reconstructed from flags as `!(ZF || SF^OF)`. Once the flag
    // expressions are folded, the exact AST is:
    //
    //   ((v == k) | ((long)(int)v < k)) == 0
    //
    // Both inner nodes are boolean, so this is precisely `v > k`; taking the
    // else arm therefore proves `v <= k`. Match the whole identity rather than
    // teaching the ladder walker about machine flags or accepting arbitrary
    // zero-tests of bitwise expressions.
    if let Some((v, k)) = lifted_signed_greater(cond) {
        match disc {
            Some(seen) if seen != &v => return None,
            Some(_) => {}
            None => *disc = Some(v),
        }
        return Some(Test::Prune(Bound::AtMost(k)));
    }

    if let Some((v, k)) = equality_on_reg(cond) {
        match disc {
            Some(seen) if seen != v => return None,
            Some(_) => {}
            None => *disc = Some(v.clone()),
        }
        return Some(Test::Case(k));
    }

    let Expr::Cmp { op, lhs, rhs } = cond else {
        return None;
    };
    // Exactly one side must be the discriminant and the other a constant, and
    // which side it is decides the direction of the bound.
    let (v, k, disc_on_left) = match (lhs.as_ref(), rhs.as_ref()) {
        (Expr::Reg(v), Expr::Const(k)) => (v, *k, true),
        (Expr::Const(k), Expr::Reg(v)) => (v, *k, false),
        _ => return None,
    };
    match disc {
        Some(seen) if seen != v => return None,
        Some(_) => {}
        None => *disc = Some(v.clone()),
    }
    match op {
        CmpOp::Eq => Some(Test::Case(k)),
        CmpOp::Ne => None, // an inverted test would swap the arms; not this shape
        // `v < k` taken means default, so not taken proves `v >= k`.
        CmpOp::Slt if disc_on_left => Some(Test::Prune(Bound::AtLeast(k))),
        // `k < v` taken means default, so not taken proves `v <= k`.
        CmpOp::Slt => Some(Test::Prune(Bound::AtMost(k))),
        // `v <= k` not taken proves `v > k`, i.e. `v >= k+1`.
        CmpOp::Sle if disc_on_left => Some(Test::Prune(Bound::AtLeast(k.checked_add(1)?))),
        // `k <= v` not taken proves `v < k`, i.e. `v <= k-1`.
        CmpOp::Sle => Some(Test::Prune(Bound::AtMost(k.checked_sub(1)?))),
        CmpOp::Ult | CmpOp::Ule => None,
    }
}

/// The exact sign-preserving 32-to-64-bit view emitted for a signed x86
/// comparison of a 32-bit switch discriminant.
fn signed_i32_view(expr: &Expr) -> Option<&VReg> {
    let Expr::Cast {
        signed: true,
        width: 8,
        expr,
    } = expr
    else {
        return None;
    };
    let Expr::Cast {
        signed: true,
        width: 4,
        expr,
    } = expr.as_ref()
    else {
        return None;
    };
    let Expr::Reg(register) = expr.as_ref() else {
        return None;
    };
    Some(register)
}

/// The exact zero-extending 32-to-64-bit view used for x86 equality/carry
/// flags. Equality still compares the same signed switch word; only its
/// canonical parent representation is unsigned.
fn unsigned_i32_view(expr: &Expr) -> Option<&VReg> {
    let Expr::Cast {
        signed: false,
        width: 8,
        expr,
    } = expr
    else {
        return None;
    };
    let Expr::Cast {
        signed: false,
        width: 4,
        expr,
    } = expr.as_ref()
    else {
        return None;
    };
    let Expr::Reg(register) = expr.as_ref() else {
        return None;
    };
    Some(register)
}

fn equality_on_reg(expr: &Expr) -> Option<(&VReg, i64)> {
    let Expr::Cmp {
        op: CmpOp::Eq,
        lhs,
        rhs,
    } = expr
    else {
        return None;
    };
    match (lhs.as_ref(), rhs.as_ref()) {
        (Expr::Reg(register), Expr::Const(value)) | (Expr::Const(value), Expr::Reg(register)) => {
            Some((register, *value))
        }
        (view, Expr::Const(value)) | (Expr::Const(value), view) => {
            unsigned_i32_view(view).map(|register| (register, i64::from(*value as u32 as i32)))
        }
        _ => None,
    }
}

fn signed_less_on_same_reg(expr: &Expr, register: &VReg, value: i64) -> bool {
    let Expr::Cmp {
        op: CmpOp::Slt,
        lhs,
        rhs,
    } = expr
    else {
        return false;
    };
    matches!(rhs.as_ref(), Expr::Const(k) if *k == value)
        && signed_i32_view(lhs).is_some_and(|seen| seen == register)
}

fn lifted_signed_greater(cond: &Expr) -> Option<(VReg, i64)> {
    let Expr::Cmp {
        op: CmpOp::Eq,
        lhs,
        rhs,
    } = cond
    else {
        return None;
    };
    let inner = match (lhs.as_ref(), rhs.as_ref()) {
        (inner, Expr::Const(0)) | (Expr::Const(0), inner) => inner,
        _ => return None,
    };
    let Expr::Bin {
        op: BinOp::Or,
        lhs,
        rhs,
    } = inner
    else {
        return None;
    };
    for (equality, less) in [(lhs.as_ref(), rhs.as_ref()), (rhs.as_ref(), lhs.as_ref())] {
        let Some((register, value)) = equality_on_reg(equality) else {
            continue;
        };
        if signed_less_on_same_reg(less, register, value) {
            return Some((register.clone(), value));
        }
    }
    None
}

/// The label a body consists of nothing but a jump to, if that is all it is.
fn sole_goto(body: &[Stmt]) -> Option<u64> {
    let mut target = None;
    for s in body {
        match s {
            Stmt::Goto { target: t } if target.is_none() => target = Some(*t),
            Stmt::Nop | Stmt::Comment(_) | Stmt::Label(_) => {}
            _ => return None,
        }
    }
    target
}

struct Ladder {
    disc: VReg,
    cases: Vec<(i64, Vec<Stmt>)>,
    default: Vec<Stmt>,
}

fn try_ladder(s: &Stmt) -> Option<Stmt> {
    let mut disc = None;
    let mut cases: Vec<(i64, Vec<Stmt>)> = Vec::new();
    // Bodies reached by a prune arm, keyed by the label they jump to. The first
    // prune arm holds the default inline and later ones `goto` its label.
    let mut default: Option<Vec<Stmt>> = None;
    let mut default_label: Option<u64> = None;

    let mut reachable = Range::full();
    let mut cur = s;
    loop {
        let Stmt::If {
            cond,
            then_body,
            else_body,
        } = cur
        else {
            // The innermost `else` with no further test on the discriminant is the
            // default, unless a prune arm already supplied one.
            let tail = std::slice::from_ref(cur);
            match (&default, sole_goto(tail)) {
                (Some(_), Some(l)) if Some(l) == default_label => {}
                (None, None) => default = Some(tail.to_vec()),
                (Some(d), None) if d == tail => {}
                _ => return None,
            }
            break;
        };
        let test = classify(cond, &mut disc)?;
        match test {
            Test::Case(k) => {
                if cases.iter().any(|(c, _)| *c == k) {
                    return None; // a repeated constant is not this shape
                }
                if !reachable.contains(k) {
                    // An earlier prune already sent this value to the default, so
                    // the tree and a `switch` would disagree about it.
                    return None;
                }
                cases.push((k, then_body.clone()));
            }
            Test::Prune(bound) => {
                reachable.narrow(&bound);
                // Either this arm holds the default inline (with its label), or it
                // jumps to the label of the one that does.
                if let Some(l) = sole_goto(then_body) {
                    match default_label {
                        Some(seen) if seen == l => {}
                        Some(_) => return None,
                        None => return None, // a jump to a label we have not seen
                    }
                } else if default.as_ref().is_some_and(|seen| seen == then_body) {
                    // Region recovery may clone a shared terminating default
                    // epilogue into every range-prune arm.  Exact AST equality
                    // proves these are still one semantic default; retain the
                    // first copy and consume the duplicates with the ladder.
                } else if default.is_none() {
                    // The label STAYS in the body. Stripping it here would dangle
                    // any `goto` from outside the tree — the renderer would pin the
                    // orphan target past the end of the function and control flow
                    // would be wrong. `prune_labels` drops it at the end iff
                    // nothing references it any more, which is the same decision
                    // made with the whole function in view.
                    default_label = leading_label(then_body);
                    default = Some(then_body.clone());
                } else {
                    return None; // a second, different default
                }
            }
        }
        // Descend into the `else`; a ladder always continues there.
        let Some(e) = else_body else { return None };
        if e.len() != 1 {
            // The tail is a sequence, not another test: it is the default.
            match &default {
                None => default = Some(e.clone()),
                Some(d) if d == e => {}
                _ => return None,
            }
            break;
        }
        cur = &e[0];
    }

    let l = Ladder {
        disc: disc?,
        cases,
        default: default?,
    };
    if l.cases.len() < MIN_CASES {
        return None;
    }
    // `default_label` is not carried out: the label lived inside the tree we are
    // replacing, and every `goto` to it was a prune arm we just consumed.
    // `recover_switches` prunes it once nothing references it.
    Some(Stmt::Switch {
        discriminant: Expr::Reg(l.disc),
        cases: l.cases.into_iter().map(|(k, b)| (Some(k), b)).collect(),
        default: Some(l.default),
    })
}

fn leading_label(body: &[Stmt]) -> Option<u64> {
    body.iter().find_map(|s| match s {
        Stmt::Label(l) => Some(*l),
        _ => None,
    })
}

/// Every label still jumped to anywhere in `body`.
fn goto_targets(body: &[Stmt]) -> std::collections::BTreeSet<u64> {
    let mut out = std::collections::BTreeSet::new();
    fn walk(body: &[Stmt], out: &mut std::collections::BTreeSet<u64>) {
        for s in body {
            match s {
                Stmt::Goto { target } => {
                    out.insert(*target);
                }
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    walk(then_body, out);
                    if let Some(b) = else_body {
                        walk(b, out);
                    }
                }
                Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => walk(body, out),
                Stmt::For {
                    init, step, body, ..
                } => {
                    walk(std::slice::from_ref(init.as_ref()), out);
                    walk(body, out);
                    walk(std::slice::from_ref(step.as_ref()), out);
                }
                Stmt::Switch { cases, default, .. } => {
                    for (_, b) in cases {
                        walk(b, out);
                    }
                    if let Some(b) = default {
                        walk(b, out);
                    }
                }
                _ => {}
            }
        }
    }
    walk(body, &mut out);
    out
}

/// Drop labels nothing jumps to any more. A `switch` that swallowed a ladder also
/// swallowed every `goto` into its default arm, and an orphan label left behind
/// renders as a stray `L_11a9: ;`.
fn prune_labels(body: &mut Vec<Stmt>, live: &std::collections::BTreeSet<u64>) {
    body.retain(|s| !matches!(s, Stmt::Label(l) if !live.contains(l)));
    for s in body.iter_mut() {
        match s {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                prune_labels(then_body, live);
                if let Some(b) = else_body {
                    prune_labels(b, live);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => prune_labels(body, live),
            Stmt::For { body, .. } => prune_labels(body, live),
            Stmt::Switch { cases, default, .. } => {
                for (_, b) in cases.iter_mut() {
                    prune_labels(b, live);
                }
                if let Some(b) = default {
                    prune_labels(b, live);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::VReg;

    fn reg(n: &str) -> Expr {
        Expr::Reg(VReg::phys(n))
    }

    fn cmp(op: CmpOp, l: Expr, r: Expr) -> Expr {
        Expr::Cmp {
            op,
            lhs: Box::new(l),
            rhs: Box::new(r),
        }
    }

    fn unsigned_i32(v: &str) -> Expr {
        Expr::Cast {
            signed: false,
            width: 8,
            expr: Box::new(Expr::Cast {
                signed: false,
                width: 4,
                expr: Box::new(reg(v)),
            }),
        }
    }

    fn assign(dst: &str, k: i64) -> Stmt {
        Stmt::Assign {
            dst: VReg::phys(dst),
            src: Expr::Const(k),
        }
    }

    /// gcc -O0's binary-search shape: `== k` alternating with a range prune, the
    /// first prune holding the default inline behind a label and the rest jumping
    /// to it.
    fn gcc_ladder(n: i64) -> Stmt {
        const L: u64 = 0x11a9;
        // Innermost first, then wrap outwards.
        let mut inner = Stmt::Goto { target: L };
        for k in 0..n {
            let case = Stmt::If {
                cond: cmp(CmpOp::Eq, reg("arg0"), Expr::Const(k)),
                then_body: vec![assign("ret", 100 + k)],
                else_body: Some(vec![inner]),
            };
            let prune_then = if k == n - 1 {
                vec![Stmt::Label(L), assign("ret", -1)]
            } else {
                vec![Stmt::Goto { target: L }]
            };
            inner = Stmt::If {
                cond: cmp(CmpOp::Slt, Expr::Const(k), reg("arg0")),
                then_body: prune_then,
                else_body: Some(vec![case]),
            };
        }
        inner
    }

    /// The order gcc actually emits: the equality test comes FIRST at each level,
    /// then the range prune. `gcc_ladder` builds the mirror of this; both must be
    /// recovered, and this is the one that appears in real output.
    fn gcc_ladder_case_first(n: i64) -> Stmt {
        const L: u64 = 0x11a9;
        let mut inner = Stmt::Goto { target: L };
        for k in 0..n {
            let prune_then = if k == n - 1 {
                vec![Stmt::Label(L), assign("ret", -1)]
            } else {
                vec![Stmt::Goto { target: L }]
            };
            let prune = Stmt::If {
                cond: cmp(CmpOp::Slt, Expr::Const(k), reg("arg0")),
                then_body: prune_then,
                else_body: Some(vec![inner]),
            };
            inner = Stmt::If {
                cond: cmp(CmpOp::Eq, reg("arg0"), Expr::Const(k)),
                then_body: vec![assign("ret", 100 + k)],
                else_body: Some(vec![prune]),
            };
        }
        inner
    }

    /// The x86 `jg` lowering that reaches this AST after flag reconstruction:
    /// `!(ZF || SF^OF)` becomes `((v == k) | ((long)(int)v < k)) == 0`.
    fn lifted_signed_greater(v: &str, k: i64) -> Expr {
        let signed_i32 = Expr::Cast {
            signed: true,
            width: 8,
            expr: Box::new(Expr::Cast {
                signed: true,
                width: 4,
                expr: Box::new(reg(v)),
            }),
        };
        cmp(
            CmpOp::Eq,
            Expr::Bin {
                op: crate::ir::types::BinOp::Or,
                lhs: Box::new(cmp(CmpOp::Eq, unsigned_i32(v), Expr::Const(k))),
                rhs: Box::new(cmp(CmpOp::Slt, signed_i32, Expr::Const(k))),
            },
            Expr::Const(0),
        )
    }

    fn real_lifted_gcc_ladder(n: i64) -> Stmt {
        const L: u64 = 0x11a9;
        let mut inner = Stmt::Goto { target: L };
        for k in 0..n {
            let prune_then = if k == n - 1 {
                vec![Stmt::Label(L), assign("ret", -1)]
            } else {
                vec![Stmt::Goto { target: L }]
            };
            let prune = Stmt::If {
                cond: lifted_signed_greater("arg0", k),
                then_body: prune_then,
                else_body: Some(vec![inner]),
            };
            inner = Stmt::If {
                cond: cmp(CmpOp::Eq, unsigned_i32("arg0"), Expr::Const(k)),
                then_body: vec![assign("ret", 100 + k)],
                else_body: Some(vec![prune]),
            };
        }
        inner
    }

    /// The same comparison tree after region recovery has cloned the shared
    /// default return into every range-prune arm.
    fn real_lifted_gcc_ladder_with_cloned_defaults(n: i64) -> Stmt {
        let default = vec![
            assign("ret", -1),
            Stmt::Return {
                value: Some(Expr::Const(-1)),
            },
        ];
        let mut inner = default.clone();
        for k in 0..n {
            let prune = Stmt::If {
                cond: lifted_signed_greater("arg0", k),
                then_body: default.clone(),
                else_body: Some(inner),
            };
            inner = vec![Stmt::If {
                cond: cmp(CmpOp::Eq, unsigned_i32("arg0"), Expr::Const(k)),
                then_body: vec![assign("ret", 100 + k)],
                else_body: Some(vec![prune]),
            }];
        }
        inner.pop().expect("one ladder root")
    }

    fn goto_case(value: i64, label: u64) -> Stmt {
        Stmt::If {
            cond: cmp(CmpOp::Eq, unsigned_i32("state"), Expr::Const(value)),
            then_body: vec![Stmt::Goto { target: label }],
            else_body: None,
        }
    }

    fn linear_goto_dispatch() -> Vec<Stmt> {
        const JOIN: u64 = 0x200;
        let mut body = vec![
            goto_case(3, 0x130),
            Stmt::If {
                cond: lifted_signed_greater("state", 3),
                then_body: vec![Stmt::Goto { target: JOIN }],
                else_body: None,
            },
            goto_case(2, 0x120),
            Stmt::If {
                cond: lifted_signed_greater("state", 2),
                then_body: vec![Stmt::Goto { target: JOIN }],
                else_body: None,
            },
            goto_case(0, 0x100),
            goto_case(1, 0x110),
            Stmt::Goto { target: JOIN },
        ];
        for (label, value) in [(0x100, 0), (0x110, 1), (0x120, 2), (0x130, 3)] {
            body.extend([
                Stmt::Label(label),
                assign("ret", value),
                Stmt::Goto { target: JOIN },
            ]);
        }
        body.extend([Stmt::Label(JOIN), Stmt::Return { value: None }]);
        body
    }

    #[test]
    fn a_linear_goto_dispatch_becomes_a_switch() {
        let mut f = Function {
            name: "fsm".into(),
            entry_va: 0x1000,
            body: linear_goto_dispatch(),
        };
        recover_switches(&mut f);

        let Stmt::Switch {
            discriminant,
            cases,
            default,
        } = &f.body[0]
        else {
            panic!("expected a switch, got:\n{:#?}", f.body);
        };
        assert_eq!(*discriminant, reg("state"));
        assert_eq!(
            cases
                .iter()
                .filter_map(|(value, _)| *value)
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
        assert!(default.is_none());
        assert!(cases.iter().all(|(_, body)| {
            !matches!(body.last(), Some(Stmt::Break)) && count_gotos_body(body, 0x200) == 0
        }));
    }

    #[test]
    fn an_external_goto_into_a_linear_case_blocks_recovery() {
        let mut body = linear_goto_dispatch();
        body.insert(0, Stmt::Goto { target: 0x100 });
        let mut f = Function {
            name: "fsm".into(),
            entry_va: 0x1000,
            body,
        };
        recover_switches(&mut f);
        assert!(!matches!(f.body.get(1), Some(Stmt::Switch { .. })));
    }

    #[test]
    fn a_fallthrough_linear_case_blocks_recovery() {
        let mut body = linear_goto_dispatch();
        let case_zero_goto = body
            .iter()
            .position(|statement| matches!(statement, Stmt::Label(0x100)))
            .expect("case zero label")
            + 2;
        body.remove(case_zero_goto);
        let mut f = Function {
            name: "fsm".into(),
            entry_va: 0x1000,
            body,
        };
        recover_switches(&mut f);
        assert!(!matches!(f.body.first(), Some(Stmt::Switch { .. })));
    }

    #[test]
    fn the_order_gcc_actually_emits_is_recovered() {
        let mut f = Function {
            name: "dispatch".into(),
            entry_va: 0x1000,
            body: vec![gcc_ladder_case_first(8), Stmt::Return { value: None }],
        };
        recover_switches(&mut f);
        let Stmt::Switch { cases, default, .. } = &f.body[0] else {
            panic!("expected a switch, got:\n{:#?}", f.body[0]);
        };
        assert_eq!(cases.len(), 8);
        assert_eq!(default.as_ref().unwrap(), &vec![assign("ret", -1)]);
        assert!(goto_targets(&f.body).is_empty(), "no goto should survive");
    }

    #[test]
    fn the_real_lifted_signed_greater_encoding_is_recovered() {
        let mut f = Function {
            name: "dispatch".into(),
            entry_va: 0x1000,
            body: vec![real_lifted_gcc_ladder(8), Stmt::Return { value: None }],
        };
        recover_switches(&mut f);
        let Stmt::Switch { cases, default, .. } = &f.body[0] else {
            panic!(
                "expected the real lifted comparison tree to become a switch:\n{:#?}",
                f.body[0]
            );
        };
        assert_eq!(cases.len(), 8);
        assert_eq!(default.as_ref().unwrap(), &vec![assign("ret", -1)]);
        assert!(goto_targets(&f.body).is_empty());
    }

    #[test]
    fn identical_cloned_default_returns_are_recovered() {
        let expected_default = vec![
            assign("ret", -1),
            Stmt::Return {
                value: Some(Expr::Const(-1)),
            },
        ];
        let mut f = Function {
            name: "dispatch".into(),
            entry_va: 0x1000,
            body: vec![real_lifted_gcc_ladder_with_cloned_defaults(8)],
        };

        recover_switches(&mut f);

        let Stmt::Switch { cases, default, .. } = &f.body[0] else {
            panic!(
                "expected cloned defaults to remain one switch default:\n{:#?}",
                f.body[0]
            );
        };
        assert_eq!(cases.len(), 8);
        assert_eq!(default.as_ref(), Some(&expected_default));
    }

    #[test]
    fn a_gcc_comparison_ladder_becomes_a_switch() {
        let mut f = Function {
            name: "dispatch".into(),
            entry_va: 0x1000,
            body: vec![gcc_ladder(8), Stmt::Return { value: None }],
        };
        recover_switches(&mut f);
        let Stmt::Switch {
            cases,
            default,
            discriminant,
        } = &f.body[0]
        else {
            panic!("expected a switch, got:\n{:#?}", f.body[0]);
        };
        assert_eq!(*discriminant, reg("arg0"));
        assert_eq!(cases.len(), 8, "one case per equality test");
        let mut ks: Vec<i64> = cases.iter().filter_map(|(k, _)| *k).collect();
        ks.sort();
        assert_eq!(ks, (0..8).collect::<Vec<_>>());
        assert_eq!(default.as_ref().unwrap(), &vec![assign("ret", -1)]);
    }

    /// The label the prune arms jumped to is consumed with them — an orphan would
    /// render as a stray `L_11a9: ;`.
    #[test]
    fn the_shared_default_label_is_consumed() {
        let mut f = Function {
            name: "dispatch".into(),
            entry_va: 0x1000,
            body: vec![gcc_ladder(8), Stmt::Return { value: None }],
        };
        recover_switches(&mut f);
        assert!(
            goto_targets(&f.body).is_empty(),
            "no goto should survive the rewrite"
        );
        fn has_label(body: &[Stmt]) -> bool {
            body.iter().any(|s| match s {
                Stmt::Label(_) => true,
                Stmt::Switch { cases, default, .. } => {
                    cases.iter().any(|(_, b)| has_label(b))
                        || default.as_ref().is_some_and(|b| has_label(b))
                }
                _ => false,
            })
        }
        assert!(!has_label(&f.body), "the orphaned label must be gone");
    }

    /// Below the threshold an if/else tree is what the source looks like too.
    #[test]
    fn a_short_ladder_is_left_alone() {
        let mut f = Function {
            name: "small".into(),
            entry_va: 0x1000,
            body: vec![gcc_ladder(2)],
        };
        let before = f.clone();
        recover_switches(&mut f);
        assert_eq!(f, before);
    }

    /// Two different values tested in one tree is not a switch.
    #[test]
    fn a_tree_testing_two_values_is_not_a_switch() {
        let mut f = Function {
            name: "mixed".into(),
            entry_va: 0x1000,
            body: vec![Stmt::If {
                cond: cmp(CmpOp::Eq, reg("arg0"), Expr::Const(1)),
                then_body: vec![assign("ret", 1)],
                else_body: Some(vec![Stmt::If {
                    cond: cmp(CmpOp::Eq, reg("arg1"), Expr::Const(2)),
                    then_body: vec![assign("ret", 2)],
                    else_body: Some(vec![Stmt::If {
                        cond: cmp(CmpOp::Eq, reg("arg0"), Expr::Const(3)),
                        then_body: vec![assign("ret", 3)],
                        else_body: Some(vec![Stmt::If {
                            cond: cmp(CmpOp::Eq, reg("arg0"), Expr::Const(4)),
                            then_body: vec![assign("ret", 4)],
                            else_body: Some(vec![assign("ret", -1)]),
                        }]),
                    }]),
                }]),
            }],
        };
        let before = f.clone();
        recover_switches(&mut f);
        assert_eq!(f, before, "arg1 in the middle disqualifies the tree");
    }

    /// A repeated constant means the tree is not a case analysis.
    #[test]
    fn a_repeated_constant_is_not_a_switch() {
        let mut f = Function {
            name: "dup".into(),
            entry_va: 0x1000,
            body: vec![Stmt::If {
                cond: cmp(CmpOp::Eq, reg("arg0"), Expr::Const(1)),
                then_body: vec![assign("ret", 1)],
                else_body: Some(vec![Stmt::If {
                    cond: cmp(CmpOp::Eq, reg("arg0"), Expr::Const(2)),
                    then_body: vec![assign("ret", 2)],
                    else_body: Some(vec![Stmt::If {
                        cond: cmp(CmpOp::Eq, reg("arg0"), Expr::Const(3)),
                        then_body: vec![assign("ret", 3)],
                        else_body: Some(vec![Stmt::If {
                            cond: cmp(CmpOp::Eq, reg("arg0"), Expr::Const(1)),
                            then_body: vec![assign("ret", 9)],
                            else_body: Some(vec![assign("ret", -1)]),
                        }]),
                    }]),
                }]),
            }],
        };
        let before = f.clone();
        recover_switches(&mut f);
        assert_eq!(f, before);
    }

    /// A prune that already excluded a constant makes a later `== that constant`
    /// UNREACHABLE. A `switch` dispatches on equality alone and would take that
    /// arm, so the rewrite would change the answer. gcc's binary search never
    /// emits this; the matcher must not rely on that.
    #[test]
    fn an_unreachable_case_blocks_the_rewrite() {
        const L: u64 = 0x11a9;
        // if (5 < v) { default } else if (v == 7) { ... } — v == 7 is dead code in
        // the tree and live in a switch.
        let mut inner = Stmt::Goto { target: L };
        for k in [7i64, 3, 2, 1] {
            inner = Stmt::If {
                cond: cmp(CmpOp::Eq, reg("arg0"), Expr::Const(k)),
                then_body: vec![assign("ret", 100 + k)],
                else_body: Some(vec![inner]),
            };
        }
        let mut f = Function {
            name: "unreachable".into(),
            entry_va: 0x1000,
            body: vec![Stmt::If {
                cond: cmp(CmpOp::Slt, Expr::Const(5), reg("arg0")),
                then_body: vec![Stmt::Label(L), assign("ret", -1)],
                else_body: Some(vec![inner]),
            }],
        };
        let before = f.clone();
        recover_switches(&mut f);
        assert_eq!(
            f, before,
            "`v == 7` is unreachable under `v <= 5`; a switch would take it"
        );
    }

    /// The same tree with every constant inside the pruned range IS a switch —
    /// the reachability check must not simply reject anything with a prune.
    #[test]
    fn cases_inside_the_pruned_range_still_recover() {
        const L: u64 = 0x11a9;
        let mut inner = Stmt::Goto { target: L };
        for k in [4i64, 3, 2, 1] {
            inner = Stmt::If {
                cond: cmp(CmpOp::Eq, reg("arg0"), Expr::Const(k)),
                then_body: vec![assign("ret", 100 + k)],
                else_body: Some(vec![inner]),
            };
        }
        let mut f = Function {
            name: "bounded".into(),
            entry_va: 0x1000,
            body: vec![Stmt::If {
                cond: cmp(CmpOp::Slt, Expr::Const(5), reg("arg0")),
                then_body: vec![Stmt::Label(L), assign("ret", -1)],
                else_body: Some(vec![inner]),
            }],
        };
        recover_switches(&mut f);
        let Stmt::Switch { cases, .. } = &f.body[0] else {
            panic!("expected a switch, got:\n{:#?}", f.body[0]);
        };
        assert_eq!(cases.len(), 4);
    }

    /// An UNSIGNED prune is not reasoned about in signed space, so those trees are
    /// left alone rather than rewritten on a bound that may not hold.
    #[test]
    fn an_unsigned_prune_is_not_rewritten() {
        const L: u64 = 0x11a9;
        let mut inner = Stmt::Goto { target: L };
        for k in [4i64, 3, 2, 1] {
            inner = Stmt::If {
                cond: cmp(CmpOp::Eq, reg("arg0"), Expr::Const(k)),
                then_body: vec![assign("ret", 100 + k)],
                else_body: Some(vec![inner]),
            };
        }
        let mut f = Function {
            name: "unsigned_prune".into(),
            entry_va: 0x1000,
            body: vec![Stmt::If {
                cond: cmp(CmpOp::Ult, Expr::Const(5), reg("arg0")),
                then_body: vec![Stmt::Label(L), assign("ret", -1)],
                else_body: Some(vec![inner]),
            }],
        };
        let before = f.clone();
        recover_switches(&mut f);
        assert_eq!(f, before);
    }

    /// A `goto` from OUTSIDE the tree into the default arm must keep its target.
    /// Dropping the label unconditionally would dangle that jump — the renderer
    /// pins an orphaned target past the end of the function, so it would still
    /// compile while branching to the wrong place.
    #[test]
    fn an_external_jump_into_the_default_arm_keeps_its_label() {
        const L: u64 = 0x11a9;
        let mut f = Function {
            name: "dispatch".into(),
            entry_va: 0x1000,
            body: vec![
                // Something before the ladder jumps straight into its default arm.
                Stmt::If {
                    cond: cmp(CmpOp::Eq, reg("arg1"), Expr::Const(0)),
                    then_body: vec![Stmt::Goto { target: L }],
                    else_body: None,
                },
                gcc_ladder(8),
                Stmt::Return { value: None },
            ],
        };
        recover_switches(&mut f);
        let Stmt::Switch { default, .. } = &f.body[1] else {
            panic!("expected a switch, got:\n{:#?}", f.body[1]);
        };
        let d = default.as_ref().expect("a default arm");
        assert!(
            d.iter().any(|s| matches!(s, Stmt::Label(l) if *l == L)),
            "the externally-referenced label must survive inside the default arm:\n{d:#?}"
        );
        assert!(
            goto_targets(&f.body).contains(&L),
            "the external goto itself must survive"
        );
    }

    /// A label that something OUTSIDE the ladder still jumps to must survive.
    #[test]
    fn a_label_reached_from_outside_is_kept() {
        const L: u64 = 0x2000;
        let mut f = Function {
            name: "outside".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Goto { target: L },
                Stmt::Label(L),
                Stmt::Return { value: None },
            ],
        };
        let before = f.clone();
        recover_switches(&mut f);
        assert_eq!(f, before, "a live label must not be pruned");
    }

    /// A ladder nested inside a loop is still recovered.
    #[test]
    fn a_ladder_inside_a_loop_is_recovered() {
        let mut f = Function {
            name: "looped".into(),
            entry_va: 0x1000,
            body: vec![Stmt::While {
                cond: Expr::Const(1),
                body: vec![gcc_ladder(8)],
            }],
        };
        recover_switches(&mut f);
        let Stmt::While { body, .. } = &f.body[0] else {
            panic!("expected the loop to survive");
        };
        assert!(
            matches!(body[0], Stmt::Switch { .. }),
            "expected a switch inside the loop, got:\n{:#?}",
            body[0]
        );
    }
}
