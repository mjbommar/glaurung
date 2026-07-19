//! Native, in-process SMT backend via the `z3` crate (links libz3).
//!
//! This is the preferred solver path: the bit-vector [`Expr`](crate::symbolic::Expr)
//! IR is translated directly into z3 AST in-process — no subprocess, no external
//! protocol, results returned as Rust values. Enabled by the `solver-z3`
//! feature.

use std::cell::RefCell;
use std::collections::BTreeMap;

use z3::ast::{Ast, Bool, BV};
use z3::{Config, Context, SatResult, Solver as Z3Native};

use crate::ir::types::{BinOp, CmpOp, UnOp, Width};
use crate::symbolic::expr::{Expr, ExprId, ExprPool};
use crate::symbolic::solver::{
    check_timeout, Assert, IncrementalSolver, Model, SolveResult, Solver, WarmAssertionPrefix,
    WarmDeltaContext, Z3ExecutionClass,
};

thread_local! {
    /// One z3 context per thread, reused across every `check`. Building a context
    /// is heavyweight (hundreds of µs); the symbolic explorer issues tens of
    /// thousands of small solves, so a fresh context per call dominated runtime.
    /// A fresh `Solver` is made per check (cheap) and its ASTs are ref-counted and
    /// freed on drop, so the shared context does not grow unbounded.
    static CTX: &'static Context = Box::leak(Box::new(Context::new(&Config::new())));
    static DIRECT_DELTA_SOLVERS: RefCell<DirectDeltaLineageZ3Solver> =
        RefCell::new(DirectDeltaLineageZ3Solver::default());
    static SERIAL_OWNER_LEASES: RefCell<BTreeMap<u64, u64>> = const { RefCell::new(BTreeMap::new()) };
}

fn configure_solver(ctx: &Context, solver: &Z3Native<'_>) {
    let mut params = z3::Params::new(ctx);
    let timeout_ms =
        u32::try_from(check_timeout().as_millis()).expect("validated check timeout fits in u32");
    params.set_u32("timeout", timeout_ms);
    solver.set_params(&params);
}

fn assertion_bool<'c>(
    ctx: &'c Context,
    pool: &ExprPool,
    (expr, expected): Assert,
    memo: &mut BTreeMap<ExprId, BV<'c>>,
) -> Bool<'c> {
    let bv = to_bv(ctx, pool, expr, memo);
    // A constraint predicate is truthy (`!= 0`) when its bit should be set.
    // `!= 0` is width-safe even if a wider value reaches the solver.
    let zero = BV::from_u64(ctx, 0, bv.get_size());
    let is_true = bv._eq(&zero).not();
    if expected {
        is_true
    } else {
        is_true.not()
    }
}

fn bv_from_u128<'c>(ctx: &'c Context, value: u128, bits: u32) -> BV<'c> {
    if bits <= 64 {
        BV::from_u64(ctx, value as u64, bits)
    } else {
        BV::from_str(ctx, bits, &value.to_string())
            .expect("a u128 decimal numeral is valid for every BV width above 64")
    }
}

fn bv_to_u128(value: &BV<'_>) -> Option<u128> {
    if let Some(value) = value.as_u64() {
        return Some(value as u128);
    }
    let rendered = value.to_string();
    if let Some(hex) = rendered.strip_prefix("#x") {
        return u128::from_str_radix(hex, 16).ok();
    }
    if let Some(binary) = rendered.strip_prefix("#b") {
        return u128::from_str_radix(binary, 2).ok();
    }
    if let Some(numeral) = rendered.strip_prefix("(_ bv") {
        return numeral
            .split_once(' ')
            .and_then(|(digits, _)| digits.parse().ok());
    }
    rendered.parse().ok()
}

fn result_with_model(
    ctx: &Context,
    solver: &Z3Native<'_>,
    result: SatResult,
    syms: &BTreeMap<u32, Width>,
) -> SolveResult {
    match result {
        SatResult::Unsat => SolveResult::Unsat,
        SatResult::Unknown => SolveResult::Unknown,
        SatResult::Sat => {
            let model = match solver.get_model() {
                Some(model) => model,
                None => return SolveResult::Error("sat but no model".into()),
            };
            let mut values = BTreeMap::new();
            for (&id, &width) in syms {
                let name = ExprPool::sym_name(id, width);
                let constant = BV::new_const(ctx, name, width.bits() as u32);
                if let Some(value) = model.eval(&constant, true).and_then(|bv| bv_to_u128(&bv)) {
                    values.insert(id, value);
                }
            }
            SolveResult::Sat(Model { values })
        }
    }
}

/// Native z3-backed solver.
#[derive(Debug, Default, Clone, Copy)]
pub struct Z3Solver;

impl Z3Solver {
    pub fn new() -> Self {
        Self
    }
}

impl Solver for Z3Solver {
    fn check(&mut self, pool: &ExprPool, asserts: &[Assert]) -> SolveResult {
        CTX.with(|ctx| {
            let ctx = *ctx;
            let solver = Z3Native::new(ctx);
            // Bound each solve: heavily-obfuscated drivers build enormous bit-vector
            // expressions whose individual solves can take many seconds. A timeout
            // makes such a solve return `unknown` (kept as feasible — a sound
            // over-approximation) instead of stalling the whole analysis.
            configure_solver(ctx, &solver);

            // One translation cache shared across all asserts of this check.
            let mut memo: BTreeMap<ExprId, BV> = BTreeMap::new();
            for &assertion in asserts {
                solver.assert(&assertion_bool(ctx, pool, assertion, &mut memo));
            }

            let mut syms = BTreeMap::new();
            for &(expr, _) in asserts {
                pool.collect_syms(expr, &mut syms);
            }
            result_with_model(ctx, &solver, solver.check(), &syms)
        })
    }
}

/// Persistent native Z3 session implementing the same explicit delta contract
/// used by Axeyum's warm lineage adapter.
#[derive(Debug)]
pub(crate) struct IncrementalZ3Solver {
    ctx: &'static Context,
    solver: Z3Native<'static>,
    symbol_scopes: Vec<BTreeMap<u32, Width>>,
}

impl IncrementalZ3Solver {
    pub(crate) fn new() -> Self {
        CTX.with(|ctx| {
            let ctx = *ctx;
            let solver = Z3Native::new(ctx);
            configure_solver(ctx, &solver);
            Self {
                ctx,
                solver,
                symbol_scopes: vec![BTreeMap::new()],
            }
        })
    }

    fn active_symbols(&self) -> BTreeMap<u32, Width> {
        let mut symbols = BTreeMap::new();
        for scope in &self.symbol_scopes {
            symbols.extend(scope.iter().map(|(&id, &width)| (id, width)));
        }
        symbols
    }
}

impl Default for IncrementalZ3Solver {
    fn default() -> Self {
        Self::new()
    }
}

impl IncrementalSolver for IncrementalZ3Solver {
    fn assert(&mut self, pool: &ExprPool, assertion: Assert) -> Result<(), String> {
        let mut memo = BTreeMap::new();
        let constraint = assertion_bool(self.ctx, pool, assertion, &mut memo);
        self.solver.assert(&constraint);
        pool.collect_syms(
            assertion.0,
            self.symbol_scopes.last_mut().expect("base scope exists"),
        );
        Ok(())
    }

    fn push(&mut self) -> Result<(), String> {
        self.solver.push();
        self.symbol_scopes.push(BTreeMap::new());
        Ok(())
    }

    fn pop(&mut self) -> bool {
        if self.symbol_scopes.len() == 1 {
            return false;
        }
        self.solver.pop(1);
        self.symbol_scopes.pop();
        true
    }

    fn scope_depth(&self) -> usize {
        self.symbol_scopes.len() - 1
    }

    fn check(&mut self) -> SolveResult {
        result_with_model(
            self.ctx,
            &self.solver,
            self.solver.check(),
            &self.active_symbols(),
        )
    }

    fn check_assuming(&mut self, pool: &ExprPool, assumptions: &[Assert]) -> SolveResult {
        let mut memo = BTreeMap::new();
        let constraints: Vec<_> = assumptions
            .iter()
            .map(|&assertion| assertion_bool(self.ctx, pool, assertion, &mut memo))
            .collect();
        let mut symbols = self.active_symbols();
        for &(expr, _) in assumptions {
            pool.collect_syms(expr, &mut symbols);
        }
        result_with_model(
            self.ctx,
            &self.solver,
            self.solver.check_assumptions(&constraints),
            &symbols,
        )
    }
}

#[derive(Debug)]
struct DirectZ3Path {
    solver: IncrementalZ3Solver,
    active_assertions: usize,
    active_prefix: WarmAssertionPrefix,
}

#[derive(Debug, Clone, Copy)]
struct DirectZ3CheckInput<'a> {
    persistent: &'a [Assert],
    persistent_prefix: &'a WarmAssertionPrefix,
    requested_retain: usize,
    temporary: &'a [Assert],
}

/// Persistent Z3 sessions keyed by the same explorer owner and driven by the
/// same exact source-prefix deltas as Axeyum's direct lineage path.
#[derive(Debug, Default)]
struct DirectDeltaLineageZ3Solver {
    paths: BTreeMap<u64, DirectZ3Path>,
}

impl DirectDeltaLineageZ3Solver {
    fn check_path(
        &mut self,
        path_id: u64,
        pool: &ExprPool,
        input: DirectZ3CheckInput<'_>,
    ) -> (SolveResult, bool, bool) {
        if input.persistent_prefix.depth() != input.persistent.len()
            || input.requested_retain > input.persistent.len()
        {
            self.paths.remove(&path_id);
            return (
                SolveResult::Error(format!(
                    "z3 direct-delta source depth {}, retain {}, persistent {}",
                    input.persistent_prefix.depth(),
                    input.requested_retain,
                    input.persistent.len()
                )),
                false,
                false,
            );
        }

        let created = !self.paths.contains_key(&path_id);
        self.paths.entry(path_id).or_insert_with(|| DirectZ3Path {
            solver: IncrementalZ3Solver::new(),
            active_assertions: 0,
            active_prefix: WarmAssertionPrefix::default(),
        });
        let retain = if created {
            0
        } else {
            self.paths
                .get(&path_id)
                .expect("Z3 path exists while deriving source LCP")
                .active_prefix
                .common_depth(input.persistent_prefix)
        };
        let result = self.transition_and_check(path_id, pool, input, retain);
        let synchronized = !matches!(result, SolveResult::Error(_));
        if !synchronized {
            self.paths.remove(&path_id);
        }
        (result, synchronized, created)
    }

    fn transition_and_check(
        &mut self,
        path_id: u64,
        pool: &ExprPool,
        input: DirectZ3CheckInput<'_>,
        retain: usize,
    ) -> SolveResult {
        let path = self
            .paths
            .get_mut(&path_id)
            .expect("Z3 path was materialized before transition");
        if retain > path.active_assertions || retain > input.persistent.len() {
            return SolveResult::Error(format!(
                "z3 direct-delta prefix {retain} exceeds active {} or persistent {}",
                path.active_assertions,
                input.persistent.len()
            ));
        }
        while path.active_assertions > retain {
            if !path.solver.pop() {
                return SolveResult::Error(
                    "z3 direct-delta scope underflow; session reset".to_string(),
                );
            }
            path.active_assertions -= 1;
        }
        for &assertion in &input.persistent[retain..] {
            if let Err(error) = path.solver.push() {
                return SolveResult::Error(error);
            }
            if let Err(error) = path.solver.assert(pool, assertion) {
                return SolveResult::Error(error);
            }
            path.active_assertions += 1;
        }
        path.active_prefix = input.persistent_prefix.clone();
        if input.temporary.is_empty() {
            path.solver.check()
        } else {
            path.solver.check_assuming(pool, input.temporary)
        }
    }

    fn close_path(&mut self, path_id: u64) -> bool {
        self.paths.remove(&path_id).is_some()
    }
}

/// Run the fixed direct-lineage Z3 cell used only by fair-shadow diagnostics.
pub(crate) fn check_warm_thread_local(
    pool: &ExprPool,
    asserts: &[Assert],
    path_id: Option<u64>,
    delta: Option<WarmDeltaContext>,
) -> (SolveResult, Z3ExecutionClass) {
    let (Some(path_id), Some(delta)) = (path_id, delta) else {
        return (
            SolveResult::Error("missing Z3 fair-shadow lineage delta".into()),
            Z3ExecutionClass::FallbackMissingDelta,
        );
    };
    if delta.persistent_assertions > asserts.len() {
        DIRECT_DELTA_SOLVERS.with(|lineage| lineage.borrow_mut().close_path(path_id));
        return (
            SolveResult::Error(format!(
                "invalid Z3 direct delta: persistent {}, total {}",
                delta.persistent_assertions,
                asserts.len()
            )),
            Z3ExecutionClass::InvalidDirectDelta,
        );
    }
    let (persistent, temporary) = asserts.split_at(delta.persistent_assertions);
    let (result, synchronized, created) = DIRECT_DELTA_SOLVERS.with(|lineage| {
        lineage.borrow_mut().check_path(
            path_id,
            pool,
            DirectZ3CheckInput {
                persistent,
                persistent_prefix: &delta.persistent_prefix,
                requested_retain: delta.retain_assertions,
                temporary,
            },
        )
    });
    let execution = if !synchronized {
        Z3ExecutionClass::InvalidDirectDelta
    } else if created {
        Z3ExecutionClass::WarmCreated
    } else {
        Z3ExecutionClass::WarmRetained
    };
    (result, execution)
}

pub(crate) fn share_serial_warm_owner_with_children(path_id: u64, children: u64) {
    debug_assert!(children > 0);
    SERIAL_OWNER_LEASES.with(|leases| {
        let mut leases = leases.borrow_mut();
        let references = leases.entry(path_id).or_insert(1);
        *references = references.saturating_add(children);
    });
}

pub(crate) fn close_warm_path(path_id: u64) {
    let close = SERIAL_OWNER_LEASES.with(|leases| {
        let mut leases = leases.borrow_mut();
        let Some(references) = leases.get_mut(&path_id) else {
            return true;
        };
        *references = references.saturating_sub(1);
        if *references == 0 {
            leases.remove(&path_id);
            true
        } else {
            false
        }
    });
    if close {
        DIRECT_DELTA_SOLVERS.with(|lineage| lineage.borrow_mut().close_path(path_id));
    }
}

/// Coerce a bit-vector to exactly `bits` wide — zero-extending if narrower,
/// truncating to the low bits if wider. This mirrors the `Concrete` domain, which
/// masks operands to each operation's declared width; z3, by contrast, rejects
/// mismatched widths (returning a null AST), so honoring the node width here keeps
/// translation total and the two domains in agreement.
fn coerce<'c>(bv: BV<'c>, bits: u32) -> BV<'c> {
    let w = bv.get_size();
    if w == bits {
        bv
    } else if w < bits {
        bv.zero_ext(bits - w)
    } else {
        bv.extract(bits - 1, 0)
    }
}

/// Translate an `Expr` into a z3 bit-vector, **memoized** over the shared
/// hash-consed DAG. Without the cache a node reachable by k paths is rebuilt 2^k
/// times — catastrophic on obfuscated code whose expressions share aggressively.
fn to_bv<'c>(
    ctx: &'c Context,
    pool: &ExprPool,
    id: ExprId,
    memo: &mut BTreeMap<ExprId, BV<'c>>,
) -> BV<'c> {
    if let Some(b) = memo.get(&id) {
        return b.clone();
    }
    let result = match *pool.get(id) {
        Expr::Const { value, width } => bv_from_u128(ctx, value, width.bits() as u32),
        Expr::Sym { id, width } => {
            BV::new_const(ctx, ExprPool::sym_name(id, width), width.bits() as u32)
        }
        Expr::Bin { op, a, b, width } => {
            let tb = width.bits() as u32;
            let a = coerce(to_bv(ctx, pool, a, memo), tb);
            let b = coerce(to_bv(ctx, pool, b, memo), tb);
            match op {
                BinOp::Add => a.bvadd(&b),
                BinOp::Sub => a.bvsub(&b),
                BinOp::Mul => a.bvmul(&b),
                BinOp::Div => a.bvudiv(&b),
                BinOp::And => a.bvand(&b),
                BinOp::Or => a.bvor(&b),
                BinOp::Xor => a.bvxor(&b),
                BinOp::Shl => a.bvshl(&b),
                BinOp::Shr => a.bvlshr(&b),
                BinOp::Sar => a.bvashr(&b),
            }
        }
        Expr::Un { op, a, .. } => {
            let a = to_bv(ctx, pool, a, memo);
            match op {
                UnOp::Not => a.bvnot(),
                UnOp::Neg => a.bvneg(),
            }
        }
        Expr::Cmp { op, a, b, width } => {
            let tb = width.bits() as u32;
            let a = coerce(to_bv(ctx, pool, a, memo), tb);
            let b = coerce(to_bv(ctx, pool, b, memo), tb);
            let cond: Bool = match op {
                CmpOp::Eq => a._eq(&b),
                CmpOp::Ne => a._eq(&b).not(),
                CmpOp::Ult => a.bvult(&b),
                CmpOp::Ule => a.bvule(&b),
                CmpOp::Slt => a.bvslt(&b),
                CmpOp::Sle => a.bvsle(&b),
            };
            cond.ite(&BV::from_u64(ctx, 1, 1), &BV::from_u64(ctx, 0, 1))
        }
        Expr::ZExt { a, from, to } => {
            let a = coerce(to_bv(ctx, pool, a, memo), from.bits() as u32);
            a.zero_ext((to.bits() - from.bits()) as u32)
        }
        Expr::SExt { a, from, to } => {
            let a = coerce(to_bv(ctx, pool, a, memo), from.bits() as u32);
            a.sign_ext((to.bits() - from.bits()) as u32)
        }
        Expr::Trunc { a, to } => {
            let tb = to.bits() as u32;
            // Ensure the source is at least `to` bits before extracting low bits.
            let a = coerce(to_bv(ctx, pool, a, memo), tb);
            a.extract(tb - 1, 0)
        }
        Expr::Extract { a, hi, lo } => {
            // Ensure the source is wide enough for the requested bit range.
            let a = coerce(to_bv(ctx, pool, a, memo), hi as u32);
            a.extract((hi - 1) as u32, lo as u32)
        }
        Expr::Concat { hi, lo, hi_w, lo_w } => {
            let h = coerce(to_bv(ctx, pool, hi, memo), hi_w.bits() as u32);
            let l = coerce(to_bv(ctx, pool, lo, memo), lo_w.bits() as u32);
            h.concat(&l)
        }
        Expr::Ite { c, t, e, width } => {
            let tb = width.bits() as u32;
            let c = to_bv(ctx, pool, c, memo);
            let t = coerce(to_bv(ctx, pool, t, memo), tb);
            let e = coerce(to_bv(ctx, pool, e, memo), tb);
            let cbool = c._eq(&BV::from_u64(ctx, 1, 1));
            cbool.ite(&t, &e)
        }
    };
    memo.insert(id, result.clone());
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::Width;
    use crate::symbolic::solver::{IncrementalSolver, WarmAssertionPrefix};

    #[test]
    fn z3_incremental_scopes_and_assumptions_restore_state() {
        let mut pool = ExprPool::new();
        let x = pool.fresh_symbol(Width::W32);
        let zero = pool.constant(Width::W32, 0);
        let one = pool.constant(Width::W32, 1);
        let eq_zero = pool.intern(Expr::Cmp {
            op: CmpOp::Eq,
            a: x,
            b: zero,
            width: Width::W32,
        });
        let eq_one = pool.intern(Expr::Cmp {
            op: CmpOp::Eq,
            a: x,
            b: one,
            width: Width::W32,
        });

        let mut solver = IncrementalZ3Solver::new();
        solver.push().unwrap();
        solver.assert(&pool, (eq_zero, true)).unwrap();
        assert_eq!(solver.scope_depth(), 1);
        match solver.check() {
            SolveResult::Sat(model) => assert_eq!(model.values.get(&0), Some(&0)),
            other => panic!("expected sat, got {other:?}"),
        }

        solver.push().unwrap();
        solver.assert(&pool, (eq_one, true)).unwrap();
        assert_eq!(solver.check(), SolveResult::Unsat);
        assert!(solver.pop());
        assert_eq!(solver.scope_depth(), 1);
        assert_eq!(
            solver.check_assuming(&pool, &[(eq_one, true)]),
            SolveResult::Unsat
        );
        assert!(matches!(solver.check(), SolveResult::Sat(_)));
        assert!(solver.pop());
        assert!(!solver.pop());
    }

    #[test]
    fn z3_preserves_u128_constants_and_model_values() {
        let mut pool = ExprPool::new();
        let x = pool.fresh_symbol(Width::W128);
        let value = (1_u128 << 100) | 0x1234_5678_9abc_def0;
        let expected = pool.intern(Expr::Const {
            value,
            width: Width::W128,
        });
        let equality = pool.intern(Expr::Cmp {
            op: CmpOp::Eq,
            a: x,
            b: expected,
            width: Width::W128,
        });
        match Z3Solver::new().check(&pool, &[(equality, true)]) {
            SolveResult::Sat(model) => assert_eq!(model.values.get(&0), Some(&value)),
            other => panic!("expected 128-bit SAT model, got {other:?}"),
        }
    }

    #[test]
    fn z3_direct_delta_lineage_rewinds_siblings_and_restores_assumptions() {
        let mut root = ExprPool::new();
        let x = root.fresh_symbol(Width::W32);
        let ten = root.constant(Width::W32, 10);
        let below_ten = root.intern(Expr::Cmp {
            op: CmpOp::Ult,
            a: x,
            b: ten,
            width: Width::W32,
        });
        let mut left = root.clone();
        let five = left.constant(Width::W32, 5);
        let x_is_five = left.intern(Expr::Cmp {
            op: CmpOp::Eq,
            a: x,
            b: five,
            width: Width::W32,
        });
        let mut right = root.clone();
        let seven = right.constant(Width::W32, 7);
        let x_is_seven = right.intern(Expr::Cmp {
            op: CmpOp::Eq,
            a: x,
            b: seven,
            width: Width::W32,
        });
        let five_right = right.constant(Width::W32, 5);
        let x_is_five_right = right.intern(Expr::Cmp {
            op: CmpOp::Eq,
            a: x,
            b: five_right,
            width: Width::W32,
        });

        let mut base = WarmAssertionPrefix::default();
        base.push();
        let mut left_prefix = base.clone();
        left_prefix.push();
        let mut right_prefix = base.clone();
        right_prefix.push();
        let mut lineage = DirectDeltaLineageZ3Solver::default();

        match lineage.check_path(
            7,
            &left,
            DirectZ3CheckInput {
                persistent: &[(below_ten, true), (x_is_five, true)],
                persistent_prefix: &left_prefix,
                requested_retain: 0,
                temporary: &[],
            },
        ) {
            (SolveResult::Sat(model), true, true) => {
                assert_eq!(model.values.get(&0), Some(&5));
            }
            other => panic!("expected newly-created left session, got {other:?}"),
        }
        match lineage.check_path(
            7,
            &right,
            DirectZ3CheckInput {
                persistent: &[(below_ten, true), (x_is_seven, true)],
                persistent_prefix: &right_prefix,
                requested_retain: 2,
                temporary: &[(x_is_five_right, true)],
            },
        ) {
            (SolveResult::Unsat, true, false) => {}
            other => panic!("expected retained right session with temporary UNSAT, got {other:?}"),
        }
        match lineage.check_path(
            7,
            &right,
            DirectZ3CheckInput {
                persistent: &[(below_ten, true), (x_is_seven, true)],
                persistent_prefix: &right_prefix,
                requested_retain: 2,
                temporary: &[],
            },
        ) {
            (SolveResult::Sat(model), true, false) => {
                assert_eq!(model.values.get(&0), Some(&7));
            }
            other => panic!("temporary assumption leaked or retained session failed: {other:?}"),
        }
        assert_eq!(left_prefix.common_depth(&right_prefix), 1);
        assert!(lineage.close_path(7));
        assert!(!lineage.close_path(7));
    }

    #[test]
    fn z3_timeout_bails_on_hard_formula() {
        // Bit-vector factoring: a * b == N (a 64-bit semiprime), with a,b > 1.
        // This is hard; the per-solve timeout must make it return `unknown`
        // quickly rather than hang (the whole point of the safety cap). If this
        // test ever hangs, the z3 timeout has regressed.
        let mut p = ExprPool::new();
        let a = p.fresh_symbol(Width::W64);
        let b = p.fresh_symbol(Width::W64);
        let prod = p.intern(Expr::Bin {
            op: BinOp::Mul,
            a,
            b,
            width: Width::W64,
        });
        // N = 1000000007 * 1000000009
        let n = p.intern(Expr::Const {
            value: 1_000_000_016_000_000_063,
            width: Width::W64,
        });
        let one = p.intern(Expr::Const {
            value: 1,
            width: Width::W64,
        });
        let eq = p.intern(Expr::Cmp {
            op: CmpOp::Eq,
            a: prod,
            b: n,
            width: Width::W64,
        });
        let a_gt = p.intern(Expr::Cmp {
            op: CmpOp::Ult,
            a: one,
            b: a,
            width: Width::W64,
        });
        let b_gt = p.intern(Expr::Cmp {
            op: CmpOp::Ult,
            a: one,
            b,
            width: Width::W64,
        });
        let start = std::time::Instant::now();
        let r = Z3Solver::new().check(&p, &[(eq, true), (a_gt, true), (b_gt, true)]);
        // The per-solve timeout must keep any single check bounded — it returns
        // a result (sat/unsat/unknown) quickly rather than hanging. If this ever
        // exceeds the bound, the z3 timeout has regressed.
        assert!(
            start.elapsed().as_secs() < 5,
            "a single solve must stay bounded, took {:?}",
            start.elapsed()
        );
        let _ = r;
    }

    #[test]
    fn z3_solves_simple_constraint() {
        // (x + 1 == 0x100) at 32 bits → x = 0xff
        let mut p = ExprPool::new();
        let x = p.fresh_symbol(Width::W32);
        let one = p.intern(Expr::Const {
            value: 1,
            width: Width::W32,
        });
        let sum = p.intern(Expr::Bin {
            op: BinOp::Add,
            a: x,
            b: one,
            width: Width::W32,
        });
        let k = p.intern(Expr::Const {
            value: 0x100,
            width: Width::W32,
        });
        let eq = p.intern(Expr::Cmp {
            op: CmpOp::Eq,
            a: sum,
            b: k,
            width: Width::W32,
        });

        match Z3Solver::new().check(&p, &[(eq, true)]) {
            SolveResult::Sat(m) => assert_eq!(m.values.get(&0).copied(), Some(0xff)),
            other => panic!("expected sat, got {:?}", other),
        }
    }

    #[test]
    fn z3_concat_coerces_to_declared_operand_widths() {
        let mut p = ExprPool::new();
        let hi = p.constant(Width(56), 0x12);
        let lo = p.constant(Width::W1, 1);
        let cat = p.intern(Expr::Concat {
            hi,
            lo,
            hi_w: Width(56),
            lo_w: Width::W8,
        });
        let expected = p.constant(Width::W64, 0x1201);
        let eq = p.intern(Expr::Cmp {
            op: CmpOp::Eq,
            a: cat,
            b: expected,
            width: Width::W64,
        });
        assert!(matches!(
            Z3Solver::new().check(&p, &[(eq, true)]),
            SolveResult::Sat(_)
        ));
    }

    #[test]
    fn z3_detects_unsat() {
        // x == 0 AND x == 1 is unsatisfiable.
        let mut p = ExprPool::new();
        let x = p.fresh_symbol(Width::W32);
        let zero = p.intern(Expr::Const {
            value: 0,
            width: Width::W32,
        });
        let onek = p.intern(Expr::Const {
            value: 1,
            width: Width::W32,
        });
        let eq0 = p.intern(Expr::Cmp {
            op: CmpOp::Eq,
            a: x,
            b: zero,
            width: Width::W32,
        });
        let eq1 = p.intern(Expr::Cmp {
            op: CmpOp::Eq,
            a: x,
            b: onek,
            width: Width::W32,
        });
        assert_eq!(
            Z3Solver::new().check(&p, &[(eq0, true), (eq1, true)]),
            SolveResult::Unsat
        );
    }
}
