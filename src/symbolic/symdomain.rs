//! The symbolic value domain — builds bit-vector [`Expr`] terms.
//!
//! Implementing [`Domain`] makes the **one** interpreter
//! (`crate::exec::interp`) produce symbolic expressions instead of concrete
//! values, with zero duplicated instruction semantics. A `Symbolic` value is an
//! [`ExprId`] into the domain's own [`ExprPool`]; `as_branch` returns a concrete
//! decision when the condition folded to a constant and otherwise asks the
//! caller to fork.

use crate::exec::domain::{BranchDecision, Domain};
use crate::exec::Concrete;
use crate::ir::types::{BinOp, CmpOp, UnOp, Width};
use crate::symbolic::expr::{Expr, ExprId, ExprPool};

/// The symbolic domain. Owns the expression pool that backs all values.
#[derive(Debug, Default, Clone)]
pub struct Symbolic {
    pub pool: ExprPool,
}

impl Symbolic {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a fresh symbolic input of the given width.
    pub fn fresh(&mut self, width: Width) -> ExprId {
        self.pool.fresh_symbol(width)
    }

    /// Render a value as an SMT-LIB2 term (for tests / solver lowering).
    pub fn render(&self, v: ExprId) -> String {
        self.pool.render_smtlib(v)
    }

    /// Evaluate a symbol-free expression DAG without asking a solver or changing
    /// its interned shape. This is intentionally separate from construction-time
    /// folding so trace/formula identities remain stable.
    fn constant_value(&self, id: ExprId) -> Option<u128> {
        fn evaluate(pool: &ExprPool, id: ExprId, dom: &mut Concrete) -> Option<u128> {
            Some(match *pool.get(id) {
                Expr::Const { value, .. } => value,
                Expr::Sym { .. } => return None,
                Expr::Bin { op, a, b, width } => {
                    let a = evaluate(pool, a, dom)?;
                    let b = evaluate(pool, b, dom)?;
                    dom.binop(op, &a, &b, width)
                }
                Expr::Un { op, a, width } => {
                    let a = evaluate(pool, a, dom)?;
                    dom.unop(op, &a, width)
                }
                Expr::Cmp { op, a, b, width } => {
                    let a = evaluate(pool, a, dom)?;
                    let b = evaluate(pool, b, dom)?;
                    dom.cmp(op, &a, &b, width)
                }
                Expr::ZExt { a, from, to } => {
                    let a = evaluate(pool, a, dom)?;
                    dom.zext(&a, from, to)
                }
                Expr::SExt { a, from, to } => {
                    let a = evaluate(pool, a, dom)?;
                    dom.sext(&a, from, to)
                }
                Expr::Trunc { a, to } => {
                    let a = evaluate(pool, a, dom)?;
                    dom.trunc(&a, to)
                }
                Expr::Extract { a, hi, lo } => {
                    let a = evaluate(pool, a, dom)?;
                    dom.extract(&a, hi, lo)
                }
                Expr::Concat { hi, lo, hi_w, lo_w } => {
                    let hi = evaluate(pool, hi, dom)?;
                    let lo = evaluate(pool, lo, dom)?;
                    dom.concat(&hi, &lo, hi_w, lo_w)
                }
                Expr::Ite { c, t, e, width } => {
                    let cond = evaluate(pool, c, dom)?;
                    let selected = if cond == 0 { e } else { t };
                    let value = evaluate(pool, selected, dom)?;
                    dom.constant(width, value)
                }
            })
        }

        evaluate(&self.pool, id, &mut Concrete)
    }
}

impl Domain for Symbolic {
    type Val = ExprId;

    fn constant(&mut self, width: Width, bits: u128) -> ExprId {
        self.pool.constant(width, bits)
    }

    fn binop(&mut self, op: BinOp, a: &ExprId, b: &ExprId, w: Width) -> ExprId {
        self.pool.intern(Expr::Bin {
            op,
            a: *a,
            b: *b,
            width: w,
        })
    }

    fn unop(&mut self, op: UnOp, a: &ExprId, w: Width) -> ExprId {
        self.pool.intern(Expr::Un {
            op,
            a: *a,
            width: w,
        })
    }

    fn cmp(&mut self, op: CmpOp, a: &ExprId, b: &ExprId, w: Width) -> ExprId {
        self.pool.intern(Expr::Cmp {
            op,
            a: *a,
            b: *b,
            width: w,
        })
    }

    fn zext(&mut self, a: &ExprId, from: Width, to: Width) -> ExprId {
        if from == to {
            return *a;
        }
        self.pool.intern(Expr::ZExt { a: *a, from, to })
    }

    fn sext(&mut self, a: &ExprId, from: Width, to: Width) -> ExprId {
        if from == to {
            return *a;
        }
        self.pool.intern(Expr::SExt { a: *a, from, to })
    }

    fn trunc(&mut self, a: &ExprId, to: Width) -> ExprId {
        self.pool.intern(Expr::Trunc { a: *a, to })
    }

    fn extract(&mut self, a: &ExprId, hi: u16, lo: u16) -> ExprId {
        self.pool.intern(Expr::Extract { a: *a, hi, lo })
    }

    fn concat(&mut self, hi: &ExprId, lo: &ExprId, hi_w: Width, lo_w: Width) -> ExprId {
        self.pool.intern(Expr::Concat {
            hi: *hi,
            lo: *lo,
            hi_w,
            lo_w,
        })
    }

    fn ite(&mut self, cond: &ExprId, t: &ExprId, e: &ExprId, w: Width) -> ExprId {
        self.pool.intern(Expr::Ite {
            c: *cond,
            t: *t,
            e: *e,
            width: w,
        })
    }

    fn as_branch(&mut self, cond: &ExprId) -> BranchDecision {
        // If the condition folded to a constant we can decide; otherwise both
        // successors are feasible and the caller must fork.
        match self.constant_value(*cond) {
            Some(0) => BranchDecision::NotTaken,
            Some(_) => BranchDecision::Taken,
            None => BranchDecision::Fork,
        }
    }

    fn as_u64(&mut self, v: &ExprId) -> Option<u64> {
        // Symbol-free DAGs are concrete too. Recognizing them here preserves
        // deterministic environment values such as an unmapped global pointer
        // assembled from zero bytes; model selection must not replace those.
        self.constant_value(*v).map(|c| c as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::domain::Domain;

    #[test]
    fn builds_constraint_term() {
        // (x + 1 == 0x100) at 32 bits, x symbolic.
        let mut d = Symbolic::new();
        let x = d.fresh(Width::W32);
        let one = d.constant(Width::W32, 1);
        let sum = d.binop(BinOp::Add, &x, &one, Width::W32);
        let k = d.constant(Width::W32, 0x100);
        let eq = d.cmp(CmpOp::Eq, &sum, &k, Width::W32);
        assert_eq!(
            d.render(eq),
            "(ite (= (bvadd sym0_32 (_ bv1 32)) (_ bv256 32)) (_ bv1 1) (_ bv0 1))"
        );
    }

    #[test]
    fn constant_condition_decides_branch() {
        let mut d = Symbolic::new();
        let t = d.constant(Width::W1, 1);
        let f = d.constant(Width::W1, 0);
        assert_eq!(d.as_branch(&t), BranchDecision::Taken);
        assert_eq!(d.as_branch(&f), BranchDecision::NotTaken);
    }

    #[test]
    fn symbolic_condition_forks() {
        let mut d = Symbolic::new();
        let x = d.fresh(Width::W32);
        let zero = d.constant(Width::W32, 0);
        let cond = d.cmp(CmpOp::Eq, &x, &zero, Width::W32);
        assert_eq!(d.as_branch(&cond), BranchDecision::Fork);
    }

    #[test]
    fn symbol_free_expression_dag_concretizes_without_a_solver() {
        let mut d = Symbolic::new();
        let zero8 = d.constant(Width::W8, 0);
        let zero16 = d.concat(&zero8, &zero8, Width::W8, Width::W8);
        let zero32 = d.concat(&zero16, &zero16, Width::W16, Width::W16);
        let zero64 = d.concat(&zero32, &zero32, Width::W32, Width::W32);
        let field = d.constant(Width::W64, 0x1e);
        let address = d.binop(BinOp::Add, &zero64, &field, Width::W64);

        assert_eq!(d.as_u64(&address), Some(0x1e));
    }

    /// The keystone: the SAME interpreter (`Machine`/`run_block`) that runs the
    /// concrete emulator, run over the `Symbolic` domain, builds a path
    /// constraint from real LLIR ops — no duplicated instruction semantics.
    #[test]
    fn one_interpreter_drives_the_symbolic_domain() {
        use crate::exec::{Flow, Machine};
        use crate::ir::types::{Flag, LlirBlock, LlirInstr, Op, VReg, Value};

        let mut m = Machine::new(Symbolic::new());
        // rdi is a symbolic 64-bit input.
        let sym = m.dom.fresh(Width::W64);
        m.regs.write(&mut m.dom, &VReg::phys("rdi"), sym);

        // rax = rdi + 1 ; zf = (rax == 0x100)
        let ops = vec![
            Op::Bin {
                dst: VReg::phys("rax"),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::phys("rdi")),
                rhs: Value::Const(1),
            },
            Op::Cmp {
                dst: VReg::Flag(Flag::Z),
                op: CmpOp::Eq,
                lhs: Value::Reg(VReg::phys("rax")),
                rhs: Value::Const(0x100),
            },
        ];
        let blk = LlirBlock {
            start_va: 0,
            end_va: 8,
            instrs: ops
                .into_iter()
                .enumerate()
                .map(|(i, op)| LlirInstr {
                    va: i as u64 * 4,
                    op,
                })
                .collect(),
            succs: vec![],
        };

        assert_eq!(m.run_block(&blk), Flow::Next);

        let zf = m.regs.read(&mut m.dom, &VReg::Flag(Flag::Z));
        let s = m.dom.render(zf);
        // The symbolic input flowed through the real interpreter into a
        // solver-ready constraint: zf == 1  iff  rdi + 1 == 0x100.
        assert_eq!(
            s,
            "(ite (= (bvadd sym0_64 (_ bv1 64)) (_ bv256 64)) (_ bv1 1) (_ bv0 1))"
        );
    }

    /// Phase-4 end-to-end: symbolically execute a block to obtain a branch
    /// condition, then ask the solver for an input that makes the branch taken.
    /// Skips the solve assertion when no SMT solver binary is installed.
    #[test]
    fn symbolic_execute_then_solve_for_input() {
        use crate::exec::Machine;
        use crate::ir::types::{Flag, LlirBlock, LlirInstr, Op, VReg, Value};
        use crate::symbolic::solver::{solve, SolveResult};

        let mut m = Machine::new(Symbolic::new());
        let sym = m.dom.fresh(Width::W64); // sym0 = rdi
        m.regs.write(&mut m.dom, &VReg::phys("rdi"), sym);

        // rax = rdi + 1 ; zf = (rax == 0x100)   → reachable iff rdi == 0xff
        let blk = LlirBlock {
            start_va: 0,
            end_va: 8,
            instrs: vec![
                LlirInstr {
                    va: 0,
                    op: Op::Bin {
                        dst: VReg::phys("rax"),
                        op: BinOp::Add,
                        lhs: Value::Reg(VReg::phys("rdi")),
                        rhs: Value::Const(1),
                    },
                },
                LlirInstr {
                    va: 4,
                    op: Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs: Value::Reg(VReg::phys("rax")),
                        rhs: Value::Const(0x100),
                    },
                },
            ],
            succs: vec![],
        };
        m.run_block(&blk);
        let zf = m.regs.read(&mut m.dom, &VReg::Flag(Flag::Z));

        match solve(&m.dom.pool, &[(zf, true)]) {
            SolveResult::Sat(model) => {
                assert_eq!(
                    model.values.get(&0).copied(),
                    Some(0xff),
                    "input that takes the branch must be rdi = 0xff"
                );
            }
            SolveResult::NoSolver => {
                eprintln!("no SMT solver on PATH — skipping solve assertion");
            }
            other => panic!("expected sat or no-solver, got {:?}", other),
        }
    }

    /// Symbolic memory works for the concolic-common case (concrete address,
    /// symbolic value): storing a symbolic value to `[rsp-8]` and loading it back
    /// preserves it. Verified semantically — `(loaded != original)` is unsat.
    #[test]
    fn symbolic_value_round_trips_through_memory() {
        use crate::exec::Machine;
        use crate::ir::types::{LlirBlock, LlirInstr, MemOp, Op, VReg, Value};
        use crate::symbolic::solver::{solve, SolveResult};

        let mut m = Machine::new(Symbolic::new());
        let rsp = m.dom.constant(Width::W64, 0x7000);
        m.regs.write(&mut m.dom, &VReg::phys("rsp"), rsp);
        let sym = m.dom.fresh(Width::W64); // sym0 = rdi
        m.regs.write(&mut m.dom, &VReg::phys("rdi"), sym);

        let blk = LlirBlock {
            start_va: 0,
            end_va: 8,
            instrs: vec![
                LlirInstr {
                    va: 0,
                    op: Op::Store {
                        addr: MemOp::plain(Some(VReg::phys("rsp")), None, 1, -8, 8),
                        src: Value::Reg(VReg::phys("rdi")),
                    },
                },
                LlirInstr {
                    va: 4,
                    op: Op::Load {
                        dst: VReg::phys("rax"),
                        addr: MemOp::plain(Some(VReg::phys("rsp")), None, 1, -8, 8),
                    },
                },
            ],
            succs: vec![],
        };
        m.run_block(&blk);

        let loaded = m.regs.read(&mut m.dom, &VReg::phys("rax"));
        let orig = m.regs.read(&mut m.dom, &VReg::phys("rdi"));
        let ne = m.dom.cmp(CmpOp::Ne, &loaded, &orig, Width::W64);
        // "loaded differs from original" must be unsatisfiable.
        match solve(&m.dom.pool, &[(ne, true)]) {
            SolveResult::Unsat => {} // round-trip preserved the value
            SolveResult::NoSolver => eprintln!("no solver — skipping"),
            other => panic!("memory round-trip not value-preserving: {:?}", other),
        }
    }
}
