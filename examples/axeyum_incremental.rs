//! Warm-reuse potential: does axeyum's incremental API close the ~2-3x gap
//! to z3 on the explorer's actual pattern (a path condition EXTENDED one
//! constraint at a time, re-checked at each step)?
//!
//! Run: cargo run --release --example axeyum_incremental --features solver-z3,solver-axeyum
//!
//! glaurung's `Solver` trait is one-shot: every fork re-passes the full
//! accumulated path condition, so solving N-deep costs O(N) *from scratch*
//! each step. axeyum's `IncrementalBvSolver` can push/assert/check, reusing
//! learned clauses across steps. We compare, over a narrowing path condition
//! (bit i of a 32-bit x is fixed to bit i of TARGET, for i in 0..K):
//!   - z3 one-shot       (glaurung's current backend behavior)
//!   - axeyum one-shot   (our native backend, current behavior)
//!   - axeyum WARM        (push/assert/check incrementally)
//! If warm is much faster than axeyum one-shot (and approaches z3), the
//! incremental Solver-trait extension (P5) is the lever to competitiveness.

use std::time::Instant;

use axeyum_ir::{Sort, TermArena};
use axeyum_solver::{CheckResult, IncrementalBvSolver, SolverConfig};
use glaurung::ir::types::{CmpOp, Width};
use glaurung::symbolic::expr::{Expr, ExprId, ExprPool};
use glaurung::symbolic::solver::axeyum_backend::AxeyumSolver;
use glaurung::symbolic::solver::z3_backend::Z3Solver;
use glaurung::symbolic::solver::{Assert, Solver};

const TARGET: u128 = 0x00C0_FFEE;
const K: usize = 24; // path-condition depth

/// Build the glaurung path condition: assert[i] fixes bit i of x to TARGET's.
fn glaurung_pc() -> (ExprPool, Vec<Assert>) {
    let mut p = ExprPool::new();
    let x = p.fresh_symbol(Width::W32);
    let mut asserts = Vec::new();
    for i in 0..K {
        let bit = ((TARGET >> i) & 1) as u128;
        // Extract bit i (glaurung hi is EXCLUSIVE): [i+1, i) -> 1-bit.
        let ex = p.intern(Expr::Extract {
            a: x,
            hi: (i + 1) as u16,
            lo: i as u16,
        });
        let b = p.intern(Expr::Const { value: bit, width: Width::W1 });
        let eq: ExprId = p.intern(Expr::Cmp { op: CmpOp::Eq, a: ex, b, width: Width::W1 });
        asserts.push((eq, true));
    }
    (p, asserts)
}

/// One-shot cost of exploring a depth-K path: at each depth d, solve the
/// conjunction of the first d constraints from scratch (what the trait does).
fn oneshot_cost<S: Solver>(mut mk: impl FnMut() -> S, p: &ExprPool, a: &[Assert]) -> f64 {
    let t = Instant::now();
    for d in 1..=a.len() {
        let _ = mk().check(p, &a[..d]);
    }
    t.elapsed().as_secs_f64() * 1000.0
}

/// Warm cost: one IncrementalBvSolver, push+assert+check per depth.
fn warm_cost() -> (f64, bool) {
    let mut arena = TermArena::new();
    let xid = arena.declare("x", Sort::BitVec(32)).unwrap();
    let x = arena.var(xid);
    let mut s = IncrementalBvSolver::with_config(SolverConfig::new());
    let mut all_sat = true;
    let t = Instant::now();
    for i in 0..K {
        let bit = ((TARGET >> i) & 1) as u128;
        let ex = arena.extract(i as u32, i as u32, x).unwrap(); // bit i, inclusive
        let b = arena.bv_const(1, bit).unwrap();
        let eq = arena.eq(ex, b).unwrap();
        s.push().unwrap();
        s.assert(&arena, eq).unwrap();
        match s.check(&arena).unwrap() {
            CheckResult::Sat(_) => {}
            _ => all_sat = false,
        }
    }
    (t.elapsed().as_secs_f64() * 1000.0, all_sat)
}

fn main() {
    let reps = 200;
    let (p, a) = glaurung_pc();

    // warm up
    let _ = oneshot_cost(Z3Solver::new, &p, &a);
    let _ = oneshot_cost(AxeyumSolver::new, &p, &a);
    let _ = warm_cost();

    let mut z3 = 0.0;
    let mut ax_os = 0.0;
    let mut ax_warm = 0.0;
    let mut sat_ok = true;
    for _ in 0..reps {
        z3 += oneshot_cost(Z3Solver::new, &p, &a);
        ax_os += oneshot_cost(AxeyumSolver::new, &p, &a);
        let (w, ok) = warm_cost();
        ax_warm += w;
        sat_ok &= ok;
    }
    z3 /= reps as f64;
    ax_os /= reps as f64;
    ax_warm /= reps as f64;

    println!("Path-condition depth K={K}, {reps} reps. Cost to explore to depth K (ms/run):");
    println!("  z3 one-shot     : {:>8.3} ms   (glaurung's current backend)", z3);
    println!("  axeyum one-shot : {:>8.3} ms   ({:.2}x vs z3)", ax_os, ax_os / z3);
    println!("  axeyum WARM     : {:>8.3} ms   ({:.2}x vs z3, {:.2}x vs axeyum one-shot)", ax_warm, ax_warm / z3, ax_warm / ax_os);
    println!("  (warm path stayed SAT throughout: {})", sat_ok);
    println!();
    println!("If axeyum WARM << axeyum one-shot, the incremental Solver-trait");
    println!("extension (P5) is the lever to close the real-workload gap.");
}
