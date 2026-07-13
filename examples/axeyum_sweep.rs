//! Mechanism micro-benchmark: sweep formula size and show WHY axeyum beats
//! the z3-crate on small formulas and converges on large ones.
//!
//! Run: cargo run --release --example axeyum_sweep --features solver-z3,solver-axeyum
//!
//! Hypothesis (the paper's core mechanism): the z3-crate backend pays a
//! large ~fixed per-query cost (FFI + context construction), roughly
//! independent of formula size; axeyum pays a small fixed cost plus a
//! bit-blast cost that grows with formula size. So z3's per-solve latency is
//! ~flat and high; axeyum's starts tiny and rises. They cross over as
//! formulas grow. We sweep two size axes to expose this:
//!   - WIDTH: bit-width of each variable.
//!   - COUNT: number of independent constrained variables (formula size).
//! Each cell is an always-SAT formula: K vars, each `x*8 + 16 == 0x90`
//! (=> x = 15), at width N.

use std::time::Instant;

use glaurung::ir::types::{BinOp, CmpOp, Width};
use glaurung::symbolic::expr::{Expr, ExprId, ExprPool};
use glaurung::symbolic::solver::axeyum_backend::AxeyumSolver;
use glaurung::symbolic::solver::z3_backend::Z3Solver;
use glaurung::symbolic::solver::{Assert, Solver};

fn build(width: Width, count: usize) -> (ExprPool, Vec<Assert>) {
    let mut p = ExprPool::new();
    let mut asserts = Vec::new();
    for _ in 0..count {
        let x = p.fresh_symbol(width);
        let eight = p.intern(Expr::Const { value: 8, width });
        let mul = p.intern(Expr::Bin { op: BinOp::Mul, a: x, b: eight, width });
        let sixteen = p.intern(Expr::Const { value: 16, width });
        let add = p.intern(Expr::Bin { op: BinOp::Add, a: mul, b: sixteen, width });
        let target = p.intern(Expr::Const { value: 0x90, width });
        let eq: ExprId = p.intern(Expr::Cmp { op: CmpOp::Eq, a: add, b: target, width });
        asserts.push((eq, true));
    }
    (p, asserts)
}

fn time_backend<S: Solver>(mut mk: impl FnMut() -> S, p: &ExprPool, a: &[Assert], reps: u32) -> f64 {
    // warm
    let _ = mk().check(p, a);
    let t = Instant::now();
    for _ in 0..reps {
        let _ = mk().check(p, a);
    }
    t.elapsed().as_nanos() as f64 / reps as f64 / 1000.0 // us/solve
}

fn main() {
    let reps: u32 = 100;
    let widths = [Width::W8, Width::W16, Width::W32, Width::W64];
    let counts = [1usize, 4, 16, 64];

    println!("Per-solve latency (us), z3 vs axeyum, {reps} reps. Cell = z3/axeyum (speedup).");
    println!();
    print!("{:>10}", "width\\count");
    for c in counts {
        print!("{:>22}", format!("K={c}"));
    }
    println!();
    println!("{}", "-".repeat(10 + 22 * counts.len()));

    for &w in &widths {
        print!("{:>10}", format!("{}b", w.bits()));
        for &c in &counts {
            let (p, a) = build(w, c);
            let z3 = time_backend(Z3Solver::new, &p, &a, reps);
            let ax = time_backend(AxeyumSolver::new, &p, &a, reps);
            print!("{:>22}", format!("{:.0}/{:.0} ({:.1}x)", z3, ax, z3 / ax));
        }
        println!();
    }

    println!();
    println!("Reading: z3 (left) is ~flat across size = fixed FFI/context floor.");
    println!("axeyum (right) starts tiny and grows with formula size = bit-blast cost.");
    println!("Speedup is largest for small formulas and shrinks as size grows.");
}
