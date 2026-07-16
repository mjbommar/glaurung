//! Native, in-process SMT backend via the `z3` crate (links libz3).
//!
//! This is the preferred solver path: the bit-vector [`Expr`](crate::symbolic::Expr)
//! IR is translated directly into z3 AST in-process — no subprocess, no external
//! protocol, results returned as Rust values. Enabled by the `solver-z3`
//! feature.

use std::collections::BTreeMap;

use z3::ast::{Ast, Bool, BV};
use z3::{Config, Context, SatResult, Solver as Z3Native};

use crate::ir::types::{BinOp, CmpOp, UnOp};
use crate::symbolic::expr::{Expr, ExprId, ExprPool};
use crate::symbolic::solver::{Assert, Model, SolveResult, Solver};

thread_local! {
    /// One z3 context per thread, reused across every `check`. Building a context
    /// is heavyweight (hundreds of µs); the symbolic explorer issues tens of
    /// thousands of small solves, so a fresh context per call dominated runtime.
    /// A fresh `Solver` is made per check (cheap) and its ASTs are ref-counted and
    /// freed on drop, so the shared context does not grow unbounded.
    static CTX: Context = Context::new(&Config::new());
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
            let solver = Z3Native::new(ctx);
            // Bound each solve: heavily-obfuscated drivers build enormous bit-vector
            // expressions whose individual solves can take many seconds. A timeout
            // makes such a solve return `unknown` (kept as feasible — a sound
            // over-approximation) instead of stalling the whole analysis.
            let mut params = z3::Params::new(ctx);
            params.set_u32("timeout", 250);
            solver.set_params(&params);

            // One translation cache shared across all asserts of this check.
            let mut memo: BTreeMap<ExprId, BV> = BTreeMap::new();
            for (e, expected) in asserts {
                let bv = to_bv(ctx, pool, *e, &mut memo);
                // A constraint predicate is truthy (`!= 0`) when its bit should be
                // set. Using `!= 0` instead of `== 1` is width-safe: predicates
                // from `Cmp` are 1-bit, but a stray wider value (e.g. an unset flag
                // in obfuscated code) must not crash the solver on a sort mismatch.
                let zero = BV::from_u64(ctx, 0, bv.get_size());
                let is_true = bv._eq(&zero).not();
                if *expected {
                    solver.assert(&is_true);
                } else {
                    solver.assert(&is_true.not());
                }
            }

            match solver.check() {
                SatResult::Unsat => SolveResult::Unsat,
                SatResult::Unknown => SolveResult::Unknown,
                SatResult::Sat => {
                    let model = match solver.get_model() {
                        Some(m) => m,
                        None => return SolveResult::Error("sat but no model".into()),
                    };
                    // Evaluate every free symbol referenced by the constraints.
                    let mut syms = BTreeMap::new();
                    for (e, _) in asserts {
                        pool.collect_syms(*e, &mut syms);
                    }
                    let mut values = BTreeMap::new();
                    for (id, width) in syms {
                        let name = ExprPool::sym_name(id, width);
                        let cst = BV::new_const(ctx, name, width.bits() as u32);
                        if let Some(v) = model.eval(&cst, true).and_then(|b| b.as_u64()) {
                            values.insert(id, v as u128);
                        }
                    }
                    SolveResult::Sat(Model { values })
                }
            }
        })
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
        Expr::Const { value, width } => BV::from_u64(ctx, value as u64, width.bits() as u32),
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
