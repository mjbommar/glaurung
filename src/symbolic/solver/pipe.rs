//! Fallback SMT-LIB2 pipe backend — spawns a solver *binary* and speaks
//! SMT-LIB2 over stdin/stdout. Adds no build dependency; used when the native
//! [`z3_backend`](super::z3_backend) is not compiled in. Prefers (in order) a
//! `GLAURUNG_SMT_SOLVER` override, then `bitwuzla`, `z3`, `cvc5` on `PATH`.

use std::collections::BTreeMap;
use std::io::Write;
use std::process::{Command, Stdio};

use crate::symbolic::expr::ExprPool;
use crate::symbolic::solver::{Assert, Model, SolveResult, Solver};

/// The subprocess SMT-LIB2 backend.
#[derive(Debug, Default, Clone, Copy)]
pub struct PipeSolver;

impl PipeSolver {
    pub fn new() -> Self {
        Self
    }
}

impl Solver for PipeSolver {
    fn check(&mut self, pool: &ExprPool, asserts: &[Assert]) -> SolveResult {
        let (script, names) = build_script(pool, asserts);
        for (prog, args) in candidate_solvers() {
            let mut child = match Command::new(&prog)
                .args(&args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
            {
                Ok(c) => c,
                Err(_) => continue, // not installed; try next candidate
            };
            if let Some(stdin) = child.stdin.as_mut() {
                if stdin.write_all(script.as_bytes()).is_err() {
                    let _ = child.wait();
                    continue;
                }
            }
            let output = match child.wait_with_output() {
                Ok(o) => o,
                Err(e) => return SolveResult::Error(e.to_string()),
            };
            let out = String::from_utf8_lossy(&output.stdout);
            let first = out.lines().next().unwrap_or("").trim();
            return match first {
                "sat" => SolveResult::Sat(parse_model(&out, &names)),
                "unsat" => SolveResult::Unsat,
                "unknown" => SolveResult::Unknown,
                other => SolveResult::Error(format!("unexpected solver output: {:?}", other)),
            };
        }
        SolveResult::NoSolver
    }
}

fn candidate_solvers() -> Vec<(String, Vec<String>)> {
    let mut v = Vec::new();
    if let Ok(custom) = std::env::var("GLAURUNG_SMT_SOLVER") {
        if !custom.is_empty() {
            v.push((custom, vec!["--lang".into(), "smt2".into()]));
        }
    }
    v.push(("bitwuzla".into(), vec!["--lang".into(), "smt2".into()]));
    v.push(("z3".into(), vec!["-in".into()]));
    v.push((
        "cvc5".into(),
        vec!["--lang".into(), "smt2".into(), "-".into()],
    ));
    v
}

/// Build the SMT-LIB2 script and the symbol-name table.
pub(crate) fn build_script(pool: &ExprPool, asserts: &[Assert]) -> (String, Vec<(u32, String)>) {
    let mut syms = BTreeMap::new();
    for (e, _) in asserts {
        pool.collect_syms(*e, &mut syms);
    }
    let mut script = String::from("(set-logic QF_BV)\n");
    let mut names = Vec::new();
    for (id, width) in &syms {
        let name = ExprPool::sym_name(*id, *width);
        script.push_str(&format!(
            "(declare-const {} (_ BitVec {}))\n",
            name,
            width.bits()
        ));
        names.push((*id, name));
    }
    for (e, expected) in asserts {
        script.push_str(&assertion_line(pool, (*e, *expected)));
    }
    script.push_str("(check-sat)\n");
    if !names.is_empty() {
        let vars: Vec<&str> = names.iter().map(|(_, n)| n.as_str()).collect();
        script.push_str(&format!("(get-value ({}))\n", vars.join(" ")));
    }
    (script, names)
}

/// Render one assertion with the same arbitrary-width truthiness semantics as
/// the native Z3 and Axeyum backends: expected true means `e != 0`, while
/// expected false means `e == 0` at `e`'s actual bit-vector width.
pub(crate) fn assertion_line(pool: &ExprPool, assertion: Assert) -> String {
    let width = pool.width_of(assertion.0).bits();
    let term = pool.render_smtlib_shared(assertion.0);
    let zero = format!("(_ bv0 {width})");
    if assertion.1 {
        format!("(assert (distinct {term} {zero}))\n")
    } else {
        format!("(assert (= {term} {zero}))\n")
    }
}

fn parse_bv_literal(s: &str) -> Option<u128> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("#x") {
        return u128::from_str_radix(hex, 16).ok();
    }
    if let Some(bin) = s.strip_prefix("#b") {
        return u128::from_str_radix(bin, 2).ok();
    }
    if let Some(rest) = s.strip_prefix("(_ bv") {
        let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        return num.parse::<u128>().ok();
    }
    None
}

fn parse_model(out: &str, names: &[(u32, String)]) -> Model {
    let mut values = BTreeMap::new();
    for (id, name) in names {
        if let Some(pos) = out.find(name.as_str()) {
            let after = &out[pos + name.len()..];
            if let Some(close) = after.find(')') {
                if let Some(v) = parse_bv_literal(after[..close].trim()) {
                    values.insert(*id, v);
                }
            }
        }
    }
    Model { values }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::{BinOp, CmpOp, Width};
    use crate::symbolic::expr::{Expr, ExprId};

    fn add1_eq_256_32() -> (ExprPool, ExprId) {
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
        (p, eq)
    }

    #[test]
    fn script_generation_is_wellformed() {
        let (p, eq) = add1_eq_256_32();
        let (script, names) = build_script(&p, &[(eq, true)]);
        assert!(script.contains("(set-logic QF_BV)"));
        assert!(script.contains("(declare-const sym0_32 (_ BitVec 32))"));
        assert!(script.contains("(check-sat)"));
        assert_eq!(names, vec![(0u32, "sym0_32".to_string())]);
    }

    #[test]
    fn script_generation_uses_width_safe_truthiness_for_wide_assertions() {
        let mut pool = ExprPool::new();
        let wide = pool.fresh_symbol(Width::W64);

        let (truthy, _) = build_script(&pool, &[(wide, true)]);
        assert!(truthy.contains("(assert (distinct sym0_64 (_ bv0 64)))"));
        let (falsey, _) = build_script(&pool, &[(wide, false)]);
        assert!(falsey.contains("(assert (= sym0_64 (_ bv0 64)))"));
    }

    #[test]
    fn script_generation_preserves_shared_expression_dags() {
        let mut pool = ExprPool::new();
        let x = pool.fresh_symbol(Width::W64);
        let one = pool.constant(Width::W64, 1);
        let mut shared = pool.intern(Expr::Bin {
            op: BinOp::Add,
            a: x,
            b: one,
            width: Width::W64,
        });
        for _ in 0..24 {
            shared = pool.intern(Expr::Bin {
                op: BinOp::Xor,
                a: shared,
                b: shared,
                width: Width::W64,
            });
        }

        let (script, _) = build_script(&pool, &[(shared, true)]);
        assert!(script.contains("(let ((g!"));
        assert_eq!(script.matches("bvxor").count(), 24);
        assert_eq!(script.matches("bvadd").count(), 1);
        assert!(
            script.len() < 4_096,
            "shared DAG expanded: {} bytes",
            script.len()
        );

        match PipeSolver::new().check(&pool, &[(shared, true)]) {
            SolveResult::Unsat => {}
            SolveResult::NoSolver => eprintln!("no solver binary on PATH - skipping"),
            other => panic!("expected repeated self-xor to be unsat, got {other:?}"),
        }
    }

    #[test]
    fn pipe_solves_or_skips() {
        let (p, eq) = add1_eq_256_32();
        match PipeSolver::new().check(&p, &[(eq, true)]) {
            SolveResult::Sat(m) => assert_eq!(m.values.get(&0).copied(), Some(0xff)),
            SolveResult::NoSolver => eprintln!("no solver binary on PATH — skipping"),
            other => panic!("expected sat or no-solver, got {:?}", other),
        }
    }

    #[test]
    fn pipe_wide_truthiness_matches_native_semantics_or_skips() {
        let mut pool = ExprPool::new();
        let wide = pool.fresh_symbol(Width::W64);
        let zero = pool.intern(Expr::Const {
            value: 0,
            width: Width::W64,
        });
        let is_zero = pool.intern(Expr::Cmp {
            op: CmpOp::Eq,
            a: wide,
            b: zero,
            width: Width::W64,
        });
        match PipeSolver::new().check(&pool, &[(wide, true), (is_zero, true)]) {
            SolveResult::Unsat => {}
            SolveResult::NoSolver => eprintln!("no solver binary on PATH — skipping"),
            other => panic!("expected wide truthiness contradiction unsat, got {other:?}"),
        }
        match PipeSolver::new().check(&pool, &[(wide, false), (is_zero, true)]) {
            SolveResult::Sat(_) => {}
            SolveResult::NoSolver => eprintln!("no solver binary on PATH — skipping"),
            other => panic!("expected wide falsey assertion sat, got {other:?}"),
        }
    }

    #[test]
    fn bv_literal_parsing() {
        assert_eq!(parse_bv_literal("#x00ff"), Some(0xff));
        assert_eq!(parse_bv_literal("#b1010"), Some(10));
        assert_eq!(parse_bv_literal("(_ bv255 32)"), Some(255));
        assert_eq!(parse_bv_literal("nonsense"), None);
    }

    #[test]
    fn model_parsing_from_getvalue_output() {
        let out = "sat\n((sym0_64 #x00000000000000ff))\n";
        let names = vec![(0u32, "sym0_64".to_string())];
        let m = parse_model(out, &names);
        assert_eq!(m.values.get(&0).copied(), Some(0xff));
    }
}
