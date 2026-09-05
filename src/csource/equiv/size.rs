//! Measuring how hard a query is *before* asking it.
//!
//! # Why this exists
//!
//! The `Solver` trait's pipe backend ([`crate::symbolic::solver::pipe`]) spawns
//! a solver binary and calls `wait_with_output()`. It sets no SMT-LIB
//! `:timeout`, passes no `-T:`, and never consults
//! [`crate::symbolic::check_timeout_ms`] --- that wall is honoured only by the
//! in-process native backends, which a build without `solver-z3` /
//! `solver-axeyum` / `solver-bitwuzla` does not have. So on the default build
//! `solve()` can run for as long as the solver wants to, and one query blocked a
//! 1,810-case sweep for over forty minutes on `55_modular_arithmetic.c::mod_pow`
//! --- twelve rounds of 64-bit multiply-and-modulo, folded over a 96-way
//! if-then-else chain, which is exactly the shape QF_BV bit-blasting is worst at.
//!
//! Fixing that belongs in `src/symbolic/solver/pipe.rs`, which is not this
//! module's to edit. What *is* this module's job is to have a bound for every
//! axis of its own work. So a query is measured first and refused when it
//! exceeds the bound, and the refusal is an ordinary
//! [`Unknown::QueryTooLarge`](super::Unknown::QueryTooLarge) with the two
//! numbers that produced it.
//!
//! # What is measured
//!
//! Two numbers, both computed by one iterative walk over the shared DAG with a
//! visited set --- linear in the DAG, never exponential, and never recursive:
//!
//! * **nodes** --- distinct expression nodes the query reaches. This is the size
//!   of the script the pipe backend renders, since it renders with sharing.
//! * **nonlinear operations** --- `Mul`, `Div` and shifts whose second operand
//!   is not a constant. Node count alone is a poor proxy for solver difficulty:
//!   a fifty-node chain of nested 64-bit multiplications is small and hard,
//!   while a twenty-thousand-node chain of adds and selects is large and easy.
//!   Counting the operations that make bit-blasting blow up separates the two.

use std::collections::BTreeSet;

use crate::ir::types::BinOp;
use crate::symbolic::expr::{Expr, ExprId, ExprPool};

/// How large and how hard a query is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QuerySize {
    /// Distinct expression nodes reachable from the query's assertions.
    pub nodes: u64,
    /// Multiplications, divisions and variable-distance shifts among them.
    pub nonlinear: u64,
}

impl QuerySize {
    /// Whether this query is within `bounds`.
    pub fn within(&self, bounds: &super::Bounds) -> bool {
        self.nodes <= bounds.max_query_nodes && self.nonlinear <= bounds.max_nonlinear_ops
    }
}

/// Measure the DAG reachable from `roots`.
///
/// Explicit stack, visited set, no recursion: the expressions this walks are
/// built by a loop unroller and are exactly the deep, heavily shared shapes a
/// recursive walk would either overflow on or re-walk exponentially.
pub fn measure(pool: &ExprPool, roots: &[ExprId]) -> QuerySize {
    let mut seen: BTreeSet<u32> = BTreeSet::new();
    let mut stack: Vec<ExprId> = roots.to_vec();
    let mut size = QuerySize::default();
    while let Some(id) = stack.pop() {
        if !seen.insert(id.0) {
            continue;
        }
        size.nodes += 1;
        match *pool.get(id) {
            Expr::Const { .. } | Expr::Sym { .. } => {}
            Expr::Bin { op, a, b, .. } => {
                if is_nonlinear(pool, op, b) {
                    size.nonlinear += 1;
                }
                stack.push(a);
                stack.push(b);
            }
            Expr::Un { a, .. }
            | Expr::ZExt { a, .. }
            | Expr::SExt { a, .. }
            | Expr::Trunc { a, .. }
            | Expr::Extract { a, .. } => stack.push(a),
            Expr::Cmp { a, b, .. } => {
                stack.push(a);
                stack.push(b);
            }
            Expr::Concat { hi, lo, .. } => {
                stack.push(hi);
                stack.push(lo);
            }
            Expr::Ite { c, t, e, .. } => {
                stack.push(c);
                stack.push(t);
                stack.push(e);
            }
        }
    }
    size
}

/// Whether this operation is one of the ones that makes bit-blasting expensive.
///
/// A multiply or divide by a literal is cheap --- it is a shift-and-add the
/// solver's preprocessor folds --- so the second operand's constness is part of
/// the question, not an afterthought.
fn is_nonlinear(pool: &ExprPool, op: BinOp, b: ExprId) -> bool {
    let variable = pool.as_const(b).is_none();
    match op {
        BinOp::Mul | BinOp::Div => variable,
        BinOp::Shl | BinOp::Shr | BinOp::Sar => variable,
        _ => false,
    }
}

/// The size of the expression **as a tree**, saturating at `cap`.
///
/// This is the number that matters for [`crate::exec::Domain::as_branch`] over
/// the symbolic domain. `Symbolic::as_branch` folds a condition by calling
/// `constant_value`, which walks the expression **recursively and without a
/// memo**, so it pays the tree cost, not the DAG cost. The two diverge fast:
/// `src/exec/memory.rs` models a 4-byte slot as four bytes, so a value that
/// round-trips through a stack slot is rebuilt as a `Concat` of four `Extract`s
/// of itself and its reference count multiplies by four. A loop counter living
/// in a frame slot therefore has a DAG that grows by a handful of nodes per
/// iteration and a *tree* that grows by a factor of four, and folding its
/// `i < n` test is what stalled a sweep for forty minutes.
///
/// Computed with an explicit stack and a memo, so this function itself is
/// linear in the DAG however large the tree it reports is.
pub fn tree_size(pool: &ExprPool, root: ExprId, cap: u128) -> u128 {
    let mut memo: std::collections::BTreeMap<u32, u128> = std::collections::BTreeMap::new();
    // Each frame is visited twice: once to push its children, once to sum them.
    let mut stack: Vec<(ExprId, bool)> = vec![(root, false)];
    while let Some((id, ready)) = stack.pop() {
        if memo.contains_key(&id.0) {
            continue;
        }
        let children = children_of(pool, id);
        if !ready {
            stack.push((id, true));
            for child in &children {
                if !memo.contains_key(&child.0) {
                    stack.push((*child, false));
                }
            }
            continue;
        }
        let mut total: u128 = 1;
        for child in &children {
            total = total.saturating_add(memo.get(&child.0).copied().unwrap_or(1));
            if total >= cap {
                total = cap;
                break;
            }
        }
        memo.insert(id.0, total);
    }
    memo.get(&root.0).copied().unwrap_or(1)
}

/// The direct children of a node, in a fixed order.
fn children_of(pool: &ExprPool, id: ExprId) -> Vec<ExprId> {
    match *pool.get(id) {
        Expr::Const { .. } | Expr::Sym { .. } => Vec::new(),
        Expr::Bin { a, b, .. } | Expr::Cmp { a, b, .. } => vec![a, b],
        Expr::Un { a, .. }
        | Expr::ZExt { a, .. }
        | Expr::SExt { a, .. }
        | Expr::Trunc { a, .. }
        | Expr::Extract { a, .. } => vec![a],
        Expr::Concat { hi, lo, .. } => vec![hi, lo],
        Expr::Ite { c, t, e, .. } => vec![c, t, e],
    }
}
