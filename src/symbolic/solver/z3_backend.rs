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
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Z3Native::new(&ctx);

        for (e, expected) in asserts {
            let bv = to_bv(&ctx, pool, *e);
            let want = BV::from_u64(&ctx, *expected as u64, 1);
            solver.assert(&bv._eq(&want));
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
                    let cst = BV::new_const(&ctx, name, width.bits() as u32);
                    if let Some(v) = model.eval(&cst, true).and_then(|b| b.as_u64()) {
                        values.insert(id, v as u128);
                    }
                }
                SolveResult::Sat(Model { values })
            }
        }
    }
}

/// Translate an `Expr` into a z3 bit-vector. Re-uses z3's structural sharing and
/// name-based const interning, so no explicit cache is needed for correctness.
fn to_bv<'c>(ctx: &'c Context, pool: &ExprPool, id: ExprId) -> BV<'c> {
    match *pool.get(id) {
        Expr::Const { value, width } => BV::from_u64(ctx, value as u64, width.bits() as u32),
        Expr::Sym { id, width } => {
            BV::new_const(ctx, ExprPool::sym_name(id, width), width.bits() as u32)
        }
        Expr::Bin { op, a, b, .. } => {
            let a = to_bv(ctx, pool, a);
            let b = to_bv(ctx, pool, b);
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
            let a = to_bv(ctx, pool, a);
            match op {
                UnOp::Not => a.bvnot(),
                UnOp::Neg => a.bvneg(),
            }
        }
        Expr::Cmp { op, a, b, .. } => {
            let a = to_bv(ctx, pool, a);
            let b = to_bv(ctx, pool, b);
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
            let a = to_bv(ctx, pool, a);
            a.zero_ext((to.bits() - from.bits()) as u32)
        }
        Expr::SExt { a, from, to } => {
            let a = to_bv(ctx, pool, a);
            a.sign_ext((to.bits() - from.bits()) as u32)
        }
        Expr::Trunc { a, to } => {
            let a = to_bv(ctx, pool, a);
            a.extract((to.bits() - 1) as u32, 0)
        }
        Expr::Extract { a, hi, lo } => {
            let a = to_bv(ctx, pool, a);
            a.extract((hi - 1) as u32, lo as u32)
        }
        Expr::Concat { hi, lo, .. } => {
            let h = to_bv(ctx, pool, hi);
            let l = to_bv(ctx, pool, lo);
            h.concat(&l)
        }
        Expr::Ite { c, t, e, .. } => {
            let c = to_bv(ctx, pool, c);
            let t = to_bv(ctx, pool, t);
            let e = to_bv(ctx, pool, e);
            let cbool = c._eq(&BV::from_u64(ctx, 1, 1));
            cbool.ite(&t, &e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::Width;

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
