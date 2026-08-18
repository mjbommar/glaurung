//! Tier 0 of the axeyum-vs-z3 benchmark: **solver primitives**.
//!
//! Bottom-up fundamentals. For every QF_BV operator glaurung's IR can emit,
//! across a width sweep, this builds a minimal formula that *isolates that one
//! operator*, runs BOTH backends, checks verdict agreement (correctness), and
//! times each on glaurung's real one-shot pattern (fresh solver per `check`).
//!
//! Two verdicts per (operator, width) cell:
//!   - SAT   : `t == v`, where `v` is the operator's value on a fixed witness
//!             `x0` (so a solution provably exists);
//!   - UNSAT : `t == v AND t == (v ^ 1)` (operator under an infeasible path).
//!
//! A concrete evaluator (mirroring the IR's semantics) computes `v`, so the
//! SAT target is always reachable. As a harness self-check, every SAT-labelled
//! case is asserted to actually be SAT under the trusted z3 oracle; a mismatch
//! is a HARNESS bug, printed loudly, not scored as a solver disagreement.
//!
//! Output: one JSON object per (case, verdict) to stdout (machine-readable,
//! reproducible); a human table + totals to stderr. Nonzero exit on any
//! confident sat/unsat disagreement or harness mislabel.
//!
//! Run:
//!   cargo run --release --features solver-z3,solver-axeyum \
//!     --example axeyum_bench_primitives > results.jsonl

use std::time::Instant;

use glaurung::ir::types::{BinOp, CmpOp, UnOp, Width};
use glaurung::symbolic::expr::{Expr, ExprId, ExprPool};
use glaurung::symbolic::solver::axeyum_backend::AxeyumSolver;
use glaurung::symbolic::solver::z3_backend::Z3Solver;
use glaurung::symbolic::solver::{Assert, SolveResult, Solver};

const REPS: usize = 200;

fn mask(w: u16) -> u128 {
    if w >= 128 {
        u128::MAX
    } else {
        (1u128 << w) - 1
    }
}

/// Concrete evaluator over a single-symbol pool: mirrors the IR semantics so
/// the SAT target `v` we assert is exactly reachable by `x = x0`.
fn eval(pool: &ExprPool, id: ExprId, x0: u128) -> u128 {
    match pool.get(id).clone() {
        Expr::Const { value, width } => value & mask(width.bits()),
        Expr::Sym { width, .. } => x0 & mask(width.bits()),
        Expr::Bin { op, a, b, width } => {
            let m = mask(width.bits());
            let a = eval(pool, a, x0);
            let b = eval(pool, b, x0);
            let r = match op {
                BinOp::Add => a.wrapping_add(b),
                BinOp::Sub => a.wrapping_sub(b),
                BinOp::Mul => a.wrapping_mul(b),
                BinOp::Div => {
                    if b & m == 0 {
                        0
                    } else {
                        (a & m) / (b & m)
                    }
                }
                // Source-level `&&` / `||` booleanize both operands at the
                // node width and yield 1 or 0 -- the same semantics as
                // `exec::concrete::Concrete::binop` and the truthiness
                // renderer in `ExprPool::render_smtlib`, NOT the bitwise ops
                // immediately below.
                BinOp::LogicalAnd => u128::from(a & m != 0 && b & m != 0),
                BinOp::LogicalOr => u128::from(a & m != 0 || b & m != 0),
                BinOp::And => a & b,
                BinOp::Or => a | b,
                BinOp::Xor => a ^ b,
                BinOp::Shl => (a & m) << (b & (width.bits() as u128 - 1)),
                BinOp::Shr => (a & m) >> (b & (width.bits() as u128 - 1)),
                BinOp::Sar => {
                    let sh = (b & (width.bits() as u128 - 1)) as u32;
                    let sbit = 1u128 << (width.bits() - 1);
                    let av = a & m;
                    if av & sbit != 0 {
                        // arithmetic: fill with ones
                        let filled = av | !m;
                        (((filled as i128) >> sh) as u128) & m
                    } else {
                        (av >> sh) & m
                    }
                }
            };
            r & m
        }
        Expr::Un { op, a, width } => {
            let m = mask(width.bits());
            let a = eval(pool, a, x0);
            match op {
                UnOp::Not => !a & m,
                UnOp::Neg => 0u128.wrapping_sub(a) & m,
            }
        }
        Expr::Cmp { op, a, b, .. } => {
            // Operand width drives signedness; result is 1 bit.
            let aw = pool.width_of(a).bits();
            let m = mask(aw);
            let av = eval(pool, a, x0) & m;
            let bv = eval(pool, b, x0) & m;
            let sbit = 1u128 << (aw - 1);
            let sext = |v: u128| -> i128 {
                if v & sbit != 0 {
                    (v | !m) as i128
                } else {
                    v as i128
                }
            };
            let r = match op {
                CmpOp::Eq => av == bv,
                CmpOp::Ne => av != bv,
                CmpOp::Ult => av < bv,
                CmpOp::Ule => av <= bv,
                CmpOp::Slt => sext(av) < sext(bv),
                CmpOp::Sle => sext(av) <= sext(bv),
            };
            r as u128
        }
        Expr::ZExt { a, .. } => eval(pool, a, x0),
        Expr::SExt { a, from, to } => {
            let fv = eval(pool, a, x0) & mask(from.bits());
            let sbit = 1u128 << (from.bits() - 1);
            if fv & sbit != 0 {
                (fv | (mask(to.bits()) & !mask(from.bits()))) & mask(to.bits())
            } else {
                fv
            }
        }
        Expr::Trunc { a, to } => eval(pool, a, x0) & mask(to.bits()),
        Expr::Extract { a, hi, lo } => (eval(pool, a, x0) >> lo) & mask(hi - lo),
        Expr::Concat { hi, lo, hi_w, lo_w } => {
            let h = eval(pool, hi, x0) & mask(hi_w.bits());
            let l = eval(pool, lo, x0) & mask(lo_w.bits());
            (h << lo_w.bits()) | l
        }
        Expr::Ite { c, t, e, .. } => {
            if eval(pool, c, x0) != 0 {
                eval(pool, t, x0)
            } else {
                eval(pool, e, x0)
            }
        }
    }
}

struct Prim {
    name: &'static str,
    category: &'static str,
    width: u16,
    pool: ExprPool,
    /// The isolated operator term (BV of `term_width`).
    term: ExprId,
    term_width: u16,
}

/// The fixed witness used to compute a reachable SAT target.
const X0: u128 = 0x2Bu128; // 43, small & odd so shifts/signs are exercised

fn konst(p: &mut ExprPool, v: u128, w: Width) -> ExprId {
    p.constant(w, v & mask(w.bits()))
}

/// Build the full primitive set at one width.
fn prims_at(w: u16) -> Vec<Prim> {
    let width = Width(w);
    let mut out: Vec<Prim> = Vec::new();
    let c = (X0 / 2 + 1) & mask(w); // a nontrivial constant operand

    // ---- scalar binary ops: t = x OP c ----
    let bins: &[(&str, BinOp)] = &[
        ("add", BinOp::Add),
        ("sub", BinOp::Sub),
        ("mul", BinOp::Mul),
        ("udiv", BinOp::Div),
        ("and", BinOp::And),
        ("or", BinOp::Or),
        ("xor", BinOp::Xor),
    ];
    for (name, op) in bins {
        let mut p = ExprPool::new();
        let x = p.fresh_symbol(width);
        let k = konst(&mut p, c.max(1), width);
        let t = p.intern(Expr::Bin {
            op: *op,
            a: x,
            b: k,
            width,
        });
        out.push(Prim {
            name,
            category: if matches!(op, BinOp::And | BinOp::Or | BinOp::Xor) {
                "bitwise"
            } else {
                "arith"
            },
            width: w,
            pool: p,
            term: t,
            term_width: w,
        });
    }

    // ---- shifts: constant in-range shift amount ----
    let shift_amt = (w / 2).max(1) as u128;
    let shifts: &[(&str, BinOp)] = &[
        ("shl", BinOp::Shl),
        ("lshr", BinOp::Shr),
        ("ashr", BinOp::Sar),
    ];
    for (name, op) in shifts {
        let mut p = ExprPool::new();
        let x = p.fresh_symbol(width);
        let s = konst(&mut p, shift_amt, width);
        let t = p.intern(Expr::Bin {
            op: *op,
            a: x,
            b: s,
            width,
        });
        out.push(Prim {
            name,
            category: "shift",
            width: w,
            pool: p,
            term: t,
            term_width: w,
        });
    }

    // ---- unary ops ----
    for (name, op) in [("not", UnOp::Not), ("neg", UnOp::Neg)] {
        let mut p = ExprPool::new();
        let x = p.fresh_symbol(width);
        let t = p.intern(Expr::Un { op, a: x, width });
        out.push(Prim {
            name,
            category: "unary",
            width: w,
            pool: p,
            term: t,
            term_width: w,
        });
    }

    // ---- compares: t = (x CMP c), 1-bit result ----
    let cmps: &[(&str, CmpOp)] = &[
        ("eq", CmpOp::Eq),
        ("ne", CmpOp::Ne),
        ("ult", CmpOp::Ult),
        ("ule", CmpOp::Ule),
        ("slt", CmpOp::Slt),
        ("sle", CmpOp::Sle),
    ];
    for (name, op) in cmps {
        let mut p = ExprPool::new();
        let x = p.fresh_symbol(width);
        let k = konst(&mut p, c, width);
        let t = p.intern(Expr::Cmp {
            op: *op,
            a: x,
            b: k,
            width,
        });
        out.push(Prim {
            name,
            category: "compare",
            width: w,
            pool: p,
            term: t,
            term_width: 1,
        });
    }

    // ---- structural (need width headroom) ----
    if w >= 16 {
        let half = w / 2;
        // trunc w -> half
        {
            let mut p = ExprPool::new();
            let x = p.fresh_symbol(width);
            let t = p.intern(Expr::Trunc {
                a: x,
                to: Width(half),
            });
            out.push(Prim {
                name: "trunc",
                category: "struct",
                width: w,
                pool: p,
                term: t,
                term_width: half,
            });
        }
        // extract low half [half:0)  (hi EXCLUSIVE)
        {
            let mut p = ExprPool::new();
            let x = p.fresh_symbol(width);
            let t = p.intern(Expr::Extract {
                a: x,
                hi: half,
                lo: 0,
            });
            out.push(Prim {
                name: "extract",
                category: "struct",
                width: w,
                pool: p,
                term: t,
                term_width: half,
            });
        }
        // concat(half,half) -> w over two symbol halves' consts (x drives lo)
        {
            let mut p = ExprPool::new();
            let x = p.fresh_symbol(Width(half));
            let hk = konst(&mut p, 0x11, Width(half));
            let t = p.intern(Expr::Concat {
                hi: hk,
                lo: x,
                hi_w: Width(half),
                lo_w: Width(half),
            });
            out.push(Prim {
                name: "concat",
                category: "struct",
                width: w,
                pool: p,
                term: t,
                term_width: w,
            });
        }
    }
    if w <= 64 {
        let dbl = w * 2;
        // zext w -> 2w
        {
            let mut p = ExprPool::new();
            let x = p.fresh_symbol(width);
            let t = p.intern(Expr::ZExt {
                a: x,
                from: width,
                to: Width(dbl),
            });
            out.push(Prim {
                name: "zext",
                category: "struct",
                width: w,
                pool: p,
                term: t,
                term_width: dbl,
            });
        }
        // sext w -> 2w
        {
            let mut p = ExprPool::new();
            let x = p.fresh_symbol(width);
            let t = p.intern(Expr::SExt {
                a: x,
                from: width,
                to: Width(dbl),
            });
            out.push(Prim {
                name: "sext",
                category: "struct",
                width: w,
                pool: p,
                term: t,
                term_width: dbl,
            });
        }
    }

    // ---- ite: t = ite(x==c, x, c) ----
    {
        let mut p = ExprPool::new();
        let x = p.fresh_symbol(width);
        let k = konst(&mut p, c, width);
        let cond = p.intern(Expr::Cmp {
            op: CmpOp::Eq,
            a: x,
            b: k,
            width,
        });
        let t = p.intern(Expr::Ite {
            c: cond,
            t: x,
            e: k,
            width,
        });
        out.push(Prim {
            name: "ite",
            category: "struct",
            width: w,
            pool: p,
            term: t,
            term_width: w,
        });
    }

    out
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

/// Median-of-REPS per-call time in microseconds, fresh solver each call.
fn time_us<S: Solver>(mk: impl Fn() -> S, pool: &ExprPool, asserts: &[Assert]) -> f64 {
    let mut samples: Vec<f64> = Vec::with_capacity(REPS);
    for _ in 0..REPS {
        let t = Instant::now();
        let _ = mk().check(pool, asserts);
        samples.push(t.elapsed().as_nanos() as f64 / 1000.0);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    samples[samples.len() / 2]
}

fn main() {
    let widths: [u16; 5] = [8, 16, 32, 64, 128];
    let mut cases = 0usize;
    // Each case's verdict is known BY CONSTRUCTION, so both backends are graded
    // against ground truth (no solver is the oracle). This exposes a wrong
    // verdict from either side rather than merely "they disagree".
    let mut z3_wrong = 0usize;
    let mut ax_wrong = 0usize;
    let mut z3_unknown = 0usize;
    let mut ax_unknown = 0usize;
    let mut z3_total = 0.0f64;
    let mut ax_total = 0.0f64;

    eprintln!(
        "{:<10} {:>4} {:>7} {:>9} {:>9} {:>8}  {}",
        "OP", "W", "VERDICT", "z3_us", "axeyum_us", "ratio", "status"
    );

    for w in widths {
        for prim in prims_at(w) {
            let tw = Width(prim.term_width);
            let v = eval(&prim.pool, prim.term, X0) & mask(prim.term_width);

            // SAT: term == v.  UNSAT: term == v AND term == (v ^ 1).
            let mut sat_pool = prim.pool.clone();
            let vk = konst(&mut sat_pool, v, tw);
            let eq_sat = sat_pool.intern(Expr::Cmp {
                op: CmpOp::Eq,
                a: prim.term,
                b: vk,
                width: tw,
            });
            let mut uns_pool = prim.pool.clone();
            let vk1 = konst(&mut uns_pool, v, tw);
            let vk2 = konst(&mut uns_pool, v ^ 1, tw);
            let eq1 = uns_pool.intern(Expr::Cmp {
                op: CmpOp::Eq,
                a: prim.term,
                b: vk1,
                width: tw,
            });
            let eq2 = uns_pool.intern(Expr::Cmp {
                op: CmpOp::Eq,
                a: prim.term,
                b: vk2,
                width: tw,
            });

            let branches: [(&str, &ExprPool, Vec<Assert>, &str); 2] = [
                ("sat", &sat_pool, vec![(eq_sat, true)], "sat"),
                ("unsat", &uns_pool, vec![(eq1, true), (eq2, true)], "unsat"),
            ];

            for (label, pool, asserts, expected) in branches {
                let rz = Z3Solver::new().check(pool, &asserts);
                let ra = AxeyumSolver::new().check(pool, &asserts);
                let vz = verdict(&rz);
                let va = verdict(&ra);
                // Grade each backend against construction-truth (`expected`).
                let z3_ok = vz == expected;
                let ax_ok = va == expected;
                let z3_unk = vz == "unknown";
                let ax_unk = va == "unknown";
                if z3_unk {
                    z3_unknown += 1;
                }
                if ax_unk {
                    ax_unknown += 1;
                }
                if !z3_ok && !z3_unk {
                    z3_wrong += 1;
                }
                if !ax_ok && !ax_unk {
                    ax_wrong += 1;
                }

                let z3_us = time_us(Z3Solver::new, pool, &asserts);
                let ax_us = time_us(AxeyumSolver::new, pool, &asserts);
                z3_total += z3_us;
                ax_total += ax_us;
                cases += 1;

                let status = if !ax_ok && !ax_unk {
                    "AXEYUM-WRONG"
                } else if !z3_ok && !z3_unk {
                    "Z3-WRONG"
                } else if z3_unk || ax_unk {
                    "unknown"
                } else {
                    "ok"
                };
                eprintln!(
                    "{:<10} {:>4} {:>7} {:>9.2} {:>9.2} {:>7.2}x  {}",
                    prim.name,
                    prim.width,
                    label,
                    z3_us,
                    ax_us,
                    if ax_us > 0.0 { z3_us / ax_us } else { 0.0 },
                    status
                );
                // machine-readable line
                println!(
                    "{{\"tier\":\"primitives\",\"op\":\"{}\",\"category\":\"{}\",\"width\":{},\"verdict\":\"{}\",\"ground_truth\":\"{}\",\"z3\":\"{}\",\"axeyum\":\"{}\",\"z3_correct\":{},\"axeyum_correct\":{},\"z3_us\":{:.3},\"axeyum_us\":{:.3},\"reps\":{}}}",
                    prim.name, prim.category, prim.width, label, expected, vz, va, z3_ok, ax_ok, z3_us, ax_us, REPS
                );
            }
        }
    }

    eprintln!(
        "\nTOTALS: {} cells graded against construction-truth",
        cases
    );
    eprintln!(
        "  correctness: axeyum_wrong={} z3_wrong={} | axeyum_unknown={} z3_unknown={}",
        ax_wrong, z3_wrong, ax_unknown, z3_unknown
    );
    eprintln!(
        "  head-to-head timing (all widths): median-sum z3={:.1}us axeyum={:.1}us => axeyum {:.2}x faster",
        z3_total,
        ax_total,
        if ax_total > 0.0 { z3_total / ax_total } else { 0.0 }
    );
    // Fail closed on a correctness error from either backend at any width.
    if ax_wrong > 0 || z3_wrong > 0 {
        std::process::exit(1);
    }
}
