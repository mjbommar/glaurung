//! Differential oracle + benchmark: z3 vs the native axeyum backend on a
//! corpus of realistic, path-condition-shaped QF_BV formulas.
//!
//! Run:
//!   cargo run --release --example axeyum_diff --features solver-z3,solver-axeyum
//!
//! For every formula it runs BOTH backends, asserts verdict agreement
//! (Sat/Unsat/Unknown), and times each. A confident disagreement (one Sat,
//! the other Unsat) is a hard error and exits non-zero. Timings feed the
//! perf comparison in the feedback log.

use std::time::Instant;

use glaurung::ir::types::{BinOp, CmpOp, Width};
use glaurung::symbolic::expr::{Expr, ExprId, ExprPool};
use glaurung::symbolic::solver::axeyum_backend::AxeyumSolver;
use glaurung::symbolic::solver::z3_backend::Z3Solver;
use glaurung::symbolic::solver::{Assert, SolveResult, Solver};

// ---- tiny builder helpers (sequential, no nested &mut borrows) ----------

fn konst(p: &mut ExprPool, v: u128, w: Width) -> ExprId {
    p.intern(Expr::Const { value: v, width: w })
}
fn bin(p: &mut ExprPool, op: BinOp, a: ExprId, b: ExprId, w: Width) -> ExprId {
    p.intern(Expr::Bin { op, a, b, width: w })
}
fn cmp(p: &mut ExprPool, op: CmpOp, a: ExprId, b: ExprId, w: Width) -> ExprId {
    p.intern(Expr::Cmp { op, a, b, width: w })
}

struct Case {
    name: &'static str,
    pool: ExprPool,
    asserts: Vec<Assert>,
}

/// Build the corpus. Each family mimics a shape that glaurung's symbolic
/// engine actually produces on driver/path analysis.
fn corpus() -> Vec<Case> {
    let mut cases = Vec::new();
    let widths = [Width::W8, Width::W16, Width::W32, Width::W64];

    // Family 1: linear solve  a*x + b == c   (sat when (c-b) divisible-ish;
    // here just multiply, engine-realistic size arithmetic).
    for (i, &w) in widths.iter().enumerate() {
        let mut p = ExprPool::new();
        let x = p.fresh_symbol(w);
        let a = konst(&mut p, 8, w);
        let ax = bin(&mut p, BinOp::Mul, x, a, w);
        let b = konst(&mut p, 0x10, w);
        let axb = bin(&mut p, BinOp::Add, ax, b, w);
        let c = konst(&mut p, 0x90, w);
        let eq = cmp(&mut p, CmpOp::Eq, axb, c, w);
        cases.push(Case {
            name: ["linear8", "linear16", "linear32", "linear64"][i],
            pool: p,
            asserts: vec![(eq, true)],
        });
    }

    // Family 2: mask + unsigned range window (IOCTL length validation shape)
    for (i, &w) in widths.iter().enumerate() {
        let mut p = ExprPool::new();
        let x = p.fresh_symbol(w);
        let mask = konst(&mut p, 0xF, w);
        let masked = bin(&mut p, BinOp::And, x, mask, w);
        let zero = konst(&mut p, 0, w);
        let low_nibble_zero = cmp(&mut p, CmpOp::Eq, masked, zero, w); // x % 16 == 0
        let hi = konst(&mut p, 0x1000, w);
        let below = cmp(&mut p, CmpOp::Ult, x, hi, w);
        let lo = konst(&mut p, 0x100, w);
        let above = cmp(&mut p, CmpOp::Ult, lo, x, w); // lo <u x
        cases.push(Case {
            name: ["mask_range8", "mask_range16", "mask_range32", "mask_range64"][i],
            pool: p,
            asserts: vec![(low_nibble_zero, true), (below, true), (above, true)],
        });
    }

    // Family 3: signed window  x <s 0  AND  x >s -10  (sat: x in [-9,-1])
    for (i, &w) in widths.iter().enumerate() {
        let mut p = ExprPool::new();
        let x = p.fresh_symbol(w);
        let zero = konst(&mut p, 0, w);
        let neg = cmp(&mut p, CmpOp::Slt, x, zero, w);
        // -10 as width-w two's complement
        let mask = if w.bits() >= 128 { u128::MAX } else { (1u128 << w.bits()) - 1 };
        let neg10 = konst(&mut p, ((-10i128) as u128) & mask, w);
        let gt = cmp(&mut p, CmpOp::Slt, neg10, x, w); // -10 <s x
        cases.push(Case {
            name: ["signed_win8", "signed_win16", "signed_win32", "signed_win64"][i],
            pool: p,
            asserts: vec![(neg, true), (gt, true)],
        });
    }

    // Family 4: overflow reachability  off + len <u off  (wrap => sat)
    for (i, &w) in widths.iter().enumerate() {
        let mut p = ExprPool::new();
        let off = p.fresh_symbol(w);
        let len = p.fresh_symbol(w);
        let sum = bin(&mut p, BinOp::Add, off, len, w);
        let wrap = cmp(&mut p, CmpOp::Ult, sum, off, w); // off+len < off => overflowed
        let zero = konst(&mut p, 0, w);
        let lenpos = cmp(&mut p, CmpOp::Ult, zero, len, w); // len > 0
        cases.push(Case {
            name: ["overflow8", "overflow16", "overflow32", "overflow64"][i],
            pool: p,
            asserts: vec![(wrap, true), (lenpos, true)],
        });
    }

    // Family 5: byte reassembly tautology  concat(extract bytes(x)) == x (sat)
    {
        let mut p = ExprPool::new();
        let x = p.fresh_symbol(Width::W32);
        let b3 = p.intern(Expr::Extract { a: x, hi: 32, lo: 24 });
        let b2 = p.intern(Expr::Extract { a: x, hi: 24, lo: 16 });
        let b1 = p.intern(Expr::Extract { a: x, hi: 16, lo: 8 });
        let b0 = p.intern(Expr::Extract { a: x, hi: 8, lo: 0 });
        let hi16 = p.intern(Expr::Concat { hi: b3, lo: b2, hi_w: Width::W8, lo_w: Width::W8 });
        let lo16 = p.intern(Expr::Concat { hi: b1, lo: b0, hi_w: Width::W8, lo_w: Width::W8 });
        let re = p.intern(Expr::Concat { hi: hi16, lo: lo16, hi_w: Width::W16, lo_w: Width::W16 });
        let eq = cmp(&mut p, CmpOp::Eq, re, x, Width::W32);
        cases.push(Case { name: "reassemble32", pool: p, asserts: vec![(eq, true)] });
    }

    // Family 6: UNSAT contradictions
    for (name, k1, k2) in [("contra_eq", 5u128, 6u128), ("contra_range", 0, 0)] {
        let mut p = ExprPool::new();
        let w = Width::W32;
        let x = p.fresh_symbol(w);
        if name == "contra_eq" {
            let a = konst(&mut p, k1, w);
            let b = konst(&mut p, k2, w);
            let e1 = cmp(&mut p, CmpOp::Eq, x, a, w);
            let e2 = cmp(&mut p, CmpOp::Eq, x, b, w);
            cases.push(Case { name, pool: p, asserts: vec![(e1, true), (e2, true)] });
        } else {
            let lo = konst(&mut p, 10, w);
            let hi = konst(&mut p, 20, w);
            let below = cmp(&mut p, CmpOp::Ult, x, lo, w); // x < 10
            let above = cmp(&mut p, CmpOp::Ult, hi, x, w); // 20 < x
            cases.push(Case { name, pool: p, asserts: vec![(below, true), (above, true)] });
        }
    }

    // Family 7: shift/mux mix (ite muxing on a symbolic selector)
    {
        let mut p = ExprPool::new();
        let w = Width::W32;
        let sel = p.fresh_symbol(Width::W8);
        let x = p.fresh_symbol(w);
        let one8 = konst(&mut p, 1, Width::W8);
        let is_one = cmp(&mut p, CmpOp::Eq, sel, one8, Width::W8); // BV1
        let four = konst(&mut p, 4, w);
        let shifted = bin(&mut p, BinOp::Shl, x, four, w);
        let ite = p.intern(Expr::Ite { c: is_one, t: shifted, e: x, width: w });
        let target = konst(&mut p, 0x1230, w);
        let eq = cmp(&mut p, CmpOp::Eq, ite, target, w);
        // sel==1 forces shifted; x<<4 == 0x1230 => x == 0x123
        let selone = cmp(&mut p, CmpOp::Eq, sel, one8, Width::W8);
        cases.push(Case { name: "ite_shift_mux", pool: p, asserts: vec![(eq, true), (selone, true)] });
    }

    cases
}

fn verdict(r: &SolveResult) -> &'static str {
    match r {
        SolveResult::Sat(_) => "sat",
        SolveResult::Unsat => "unsat",
        SolveResult::Unknown(_) => "unknown",
        SolveResult::NoSolver => "nosolver",
        SolveResult::Error(_) => "error",
    }
}

fn main() {
    const REPS: u32 = 50; // benchmark repetitions per formula
    let cases = corpus();
    println!(
        "{:<16} {:>7} {:>7} {:>10} {:>10} {:>7}",
        "case", "z3", "axeyum", "z3_us/op", "ax_us/op", "ratio"
    );
    println!("{}", "-".repeat(64));

    let mut disagreements = 0usize;
    let mut z3_total_ns = 0u128;
    let mut ax_total_ns = 0u128;

    for case in &cases {
        let mut z3 = Z3Solver::new();
        let mut ax = AxeyumSolver::new();

        // Correctness: one authoritative solve each.
        let rz = z3.check(&case.pool, &case.asserts);
        let ra = ax.check(&case.pool, &case.asserts);
        let vz = verdict(&rz);
        let va = verdict(&ra);
        let agree = vz == va
            || matches!(vz, "unknown") // unknown asymmetry tolerated (soundness)
            || matches!(va, "unknown");
        let confident_disagree = matches!((vz, va), ("sat", "unsat") | ("unsat", "sat"));
        if confident_disagree {
            disagreements += 1;
        }

        // Benchmark: REPS solves each (fresh solver per call, mirroring the
        // engine's one-shot usage).
        let t0 = Instant::now();
        for _ in 0..REPS {
            let _ = Z3Solver::new().check(&case.pool, &case.asserts);
        }
        let z3_ns = t0.elapsed().as_nanos();
        let t1 = Instant::now();
        for _ in 0..REPS {
            let _ = AxeyumSolver::new().check(&case.pool, &case.asserts);
        }
        let ax_ns = t1.elapsed().as_nanos();
        z3_total_ns += z3_ns;
        ax_total_ns += ax_ns;

        let z3_us = z3_ns as f64 / REPS as f64 / 1000.0;
        let ax_us = ax_ns as f64 / REPS as f64 / 1000.0;
        let flag = if confident_disagree { " <== DISAGREE" } else if !agree { " (unknown)" } else { "" };
        println!(
            "{:<16} {:>7} {:>7} {:>10.1} {:>10.1} {:>6.2}x{}",
            case.name, vz, va, z3_us, ax_us, ax_us / z3_us, flag
        );
    }

    println!("{}", "-".repeat(64));
    println!(
        "TOTALS: {} cases, {} confident disagreements | z3 {:.2} ms, axeyum {:.2} ms, ratio {:.2}x",
        cases.len(),
        disagreements,
        z3_total_ns as f64 / 1e6,
        ax_total_ns as f64 / 1e6,
        ax_total_ns as f64 / z3_total_ns as f64
    );
    if disagreements > 0 {
        eprintln!("FAIL: {} confident sat/unsat disagreements", disagreements);
        std::process::exit(1);
    }
    println!("OK: verdicts agree across all cases (unknowns tolerated).");
}
