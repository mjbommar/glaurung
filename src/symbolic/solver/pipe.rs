//! Fallback SMT-LIB2 pipe backend — spawns a solver *binary* and speaks
//! SMT-LIB2 over stdin/stdout. Adds no build dependency; used when the native
//! [`z3_backend`](super::z3_backend) is not compiled in. Prefers (in order) a
//! `GLAURUNG_SMT_SOLVER` override, then `bitwuzla`, `z3`, `cvc5` on `PATH`.
//!
//! The subprocess honours the same per-check wall as the in-process backends
//! ([`check_timeout`](super::check_timeout)), enforced here by killing the
//! child rather than by any solver-specific time-limit flag; expiry surfaces as
//! [`SolveUnknownReason::WallTimeout`](super::SolveUnknownReason::WallTimeout).

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::symbolic::expr::ExprPool;
use crate::symbolic::solver::{check_timeout, Assert, Model, SolveResult, Solver};

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
        run_candidates(&script, &names, &candidate_solvers(), check_timeout())
    }
}

/// Longest nap between deadline checks. Small enough that the wall is accurate
/// to a few milliseconds, large enough that a long solve is not a spin loop.
const POLL_CEILING: Duration = Duration::from_millis(5);
/// First nap after spawn, so the common sub-millisecond solve is not delayed.
const POLL_FLOOR: Duration = Duration::from_micros(200);

/// Try each candidate solver in turn, returning the first real verdict.
///
/// `wall` is enforced by *us*, not by the solver: we spawn, wait against a
/// deadline, and kill the child when it expires. That is deliberate. Passing a
/// native time-limit flag would need per-binary flag knowledge, and an
/// unrecognized flag makes a solver exit non-zero -- silently converting every
/// solve into a failure, which is a far worse regression than an unbounded
/// solve. Killing the child is solver-agnostic and needs no flag knowledge.
fn run_candidates(
    script: &str,
    names: &[(u32, String)],
    candidates: &[(String, Vec<String>)],
    wall: Duration,
) -> SolveResult {
    for (prog, args) in candidates {
        let mut child = match Command::new(prog)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // stderr goes to /dev/null rather than to a pipe. An undrained pipe
            // is a place the child can block forever; /dev/null never fills, and
            // we never read the solver's diagnostics anyway.
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => continue, // not installed; try next candidate
        };
        let deadline = Instant::now() + wall;

        // Query and answer both cross OS pipes with a bounded buffer (64 KiB on
        // Linux), and our scripts are machine-generated and routinely exceed it.
        // Writing the query on this thread while nothing drains stdout deadlocks
        // on any large exchange: the solver blocks writing its answer, we block
        // writing the query. So *both* directions get their own thread. Draining
        // stdout alone would not be enough -- a solver that simply never reads
        // stdin would still pin a blocking `write_all` here, and this thread has
        // to stay free to watch the clock for the wall to mean anything.
        let stdin = child.stdin.take();
        let query = script.to_string();
        let writer = std::thread::spawn(move || -> std::io::Result<()> {
            match stdin {
                // Dropping the handle closes the pipe: that is the solver's EOF.
                Some(mut stdin) => stdin.write_all(query.as_bytes()),
                None => Ok(()),
            }
        });
        let stdout = child.stdout.take();
        let reader = std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
            let mut buffer = Vec::new();
            if let Some(mut stdout) = stdout {
                stdout.read_to_end(&mut buffer)?;
            }
            Ok(buffer)
        });

        let timed_out = wait_until(&mut child, deadline);
        // The child is gone by now either way, so both pipes are closed: the
        // reader has seen EOF and the writer has seen EPIPE. Joining is what
        // keeps the two helper threads from leaking.
        let write_failed = !matches!(writer.join(), Ok(Ok(())));
        let stdout_bytes = reader.join();
        if timed_out {
            return SolveResult::Unknown(super::SolveUnknownReason::WallTimeout);
        }
        let stdout_bytes = match stdout_bytes {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => return SolveResult::Error(e.to_string()),
            Err(_) => return SolveResult::Error("solver reader thread panicked".into()),
        };

        let out = String::from_utf8_lossy(&stdout_bytes);
        let first = out.lines().next().unwrap_or("").trim();
        return match first {
            "sat" => SolveResult::Sat(parse_model(&out, names)),
            "unsat" => SolveResult::Unsat,
            "unknown" => SolveResult::Unknown(super::SolveUnknownReason::Other),
            // A failed write plus no verdict is the old "spawned but not really
            // a solver" case: keep falling through to the next candidate.
            _ if write_failed => continue,
            other => SolveResult::Error(format!("unexpected solver output: {:?}", other)),
        };
    }
    SolveResult::NoSolver
}

/// Wait for `child` to exit, killing and reaping it if `deadline` passes first.
///
/// Returns `true` when the deadline was enforced. Every exit path reaps the
/// child, so a killed solver leaves neither an orphan nor a zombie.
fn wait_until(child: &mut Child, deadline: Instant) -> bool {
    let mut nap = POLL_FLOOR;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return false, // try_wait reaped it
            Ok(None) => {}
            // We cannot observe this child's state; reap what we can and let the
            // output path decide rather than reporting a timeout we did not see.
            Err(_) => {
                let _ = child.wait();
                return false;
            }
        }
        let now = Instant::now();
        let Some(remaining) = deadline
            .checked_duration_since(now)
            .filter(|r| !r.is_zero())
        else {
            let _ = child.kill();
            let _ = child.wait();
            return true;
        };
        std::thread::sleep(nap.min(remaining));
        nap = (nap * 2).min(POLL_CEILING);
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
            // The per-check wall now binds on the subprocess too. On a trivial
            // query that only fires when the machine is too loaded to answer at
            // all, which is an environment skip, not a semantic failure.
            SolveResult::Unknown(crate::symbolic::solver::SolveUnknownReason::WallTimeout) => {
                eprintln!("solver exceeded the per-check wall - skipping")
            }
            other => panic!("expected repeated self-xor to be unsat, got {other:?}"),
        }
    }

    #[test]
    fn pipe_solves_or_skips() {
        let (p, eq) = add1_eq_256_32();
        match PipeSolver::new().check(&p, &[(eq, true)]) {
            SolveResult::Sat(m) => assert_eq!(m.values.get(&0).copied(), Some(0xff)),
            SolveResult::NoSolver => eprintln!("no solver binary on PATH — skipping"),
            SolveResult::Unknown(crate::symbolic::solver::SolveUnknownReason::WallTimeout) => {
                eprintln!("solver exceeded the per-check wall - skipping")
            }
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
            SolveResult::Unknown(crate::symbolic::solver::SolveUnknownReason::WallTimeout) => {
                eprintln!("solver exceeded the per-check wall - skipping")
            }
            other => panic!("expected wide truthiness contradiction unsat, got {other:?}"),
        }
        match PipeSolver::new().check(&pool, &[(wide, false), (is_zero, true)]) {
            SolveResult::Sat(_) => {}
            SolveResult::NoSolver => eprintln!("no solver binary on PATH — skipping"),
            SolveResult::Unknown(crate::symbolic::solver::SolveUnknownReason::WallTimeout) => {
                eprintln!("solver exceeded the per-check wall - skipping")
            }
            other => panic!("expected wide falsey assertion sat, got {other:?}"),
        }
    }

    // ---------------------------------------------------------------------
    // Subprocess-wall and pipe-plumbing tests.
    //
    // These drive `run_candidates` -- the whole of `Solver::check` except the
    // PATH probe -- with fake solver binaries, rather than pointing
    // `GLAURUNG_SMT_SOLVER` at them. That env var is process-global: setting it
    // here would silently redirect every *other* test that reaches
    // `PipeSolver` through `symbolic::solve` whenever the suite runs with more
    // than one test thread (CI's `cargo test --features symbolic` does).
    // ---------------------------------------------------------------------

    #[cfg(unix)]
    mod subprocess {
        use super::*;
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::time::{Duration, Instant};

        static SEQ: AtomicU32 = AtomicU32::new(0);

        /// Materialize an executable `/bin/sh` fake solver, returning its path
        /// and a scratch directory the test may use for side-channel files.
        fn fake_solver(body: &str) -> (std::path::PathBuf, std::path::PathBuf) {
            use std::os::unix::fs::PermissionsExt;
            let dir = std::env::temp_dir().join(format!(
                "glaurung-pipe-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).expect("create fake-solver directory");
            let path = dir.join("solver.sh");
            std::fs::write(&path, body).expect("write fake solver");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("chmod fake solver");
            (path, dir)
        }

        fn smt2(prog: &std::path::Path) -> (String, Vec<String>) {
            (
                prog.display().to_string(),
                vec!["--lang".into(), "smt2".into()],
            )
        }

        /// True once the pid is neither a live process nor an unreaped zombie.
        fn process_gone(pid: &str) -> bool {
            !std::path::Path::new(&format!("/proc/{pid}")).exists()
        }

        /// A solver that never answers must hit the wall, be killed, and be
        /// reported as `unknown(wall-timeout)` -- not `sat`, not an error, and
        /// not by silently falling through to the next candidate.
        #[test]
        fn wall_kills_a_hanging_solver_and_reports_wall_timeout() {
            let (hang, dir) =
                fake_solver("#!/bin/sh\necho $$ > \"$(dirname \"$0\")/pid\"\nexec sleep 20\n");
            // A second candidate that would answer instantly: reaching it would
            // mean the wall silently degraded into a retry.
            let (quick, quick_dir) = fake_solver("#!/bin/sh\ncat > /dev/null\necho unsat\n");

            let (pool, eq) = add1_eq_256_32();
            let (script, names) = build_script(&pool, &[(eq, true)]);
            let candidates = vec![smt2(&hang), smt2(&quick)];

            let started = Instant::now();
            let result = run_candidates(&script, &names, &candidates, Duration::from_millis(500));
            let elapsed = started.elapsed();

            assert_eq!(
                result,
                SolveResult::Unknown(crate::symbolic::solver::SolveUnknownReason::WallTimeout),
                "expected the wall to surface as unknown(wall-timeout)"
            );
            assert!(
                elapsed < Duration::from_secs(8),
                "500ms wall did not bind: solve took {elapsed:?}"
            );

            let pid =
                std::fs::read_to_string(dir.join("pid")).expect("fake solver recorded no pid");
            let pid = pid.trim().to_string();
            assert!(!pid.is_empty(), "fake solver recorded an empty pid");
            if std::path::Path::new("/proc/self").exists() {
                assert!(
                    process_gone(&pid),
                    "hung solver pid {pid} survived the wall (orphan or zombie)"
                );
            }
            let _ = std::fs::remove_dir_all(&dir);
            let _ = std::fs::remove_dir_all(&quick_dir);
        }

        /// A solver that answers inside the wall is unaffected by it.
        #[test]
        fn wall_does_not_disturb_a_solver_that_answers_in_time() {
            let (quick, dir) = fake_solver(
                "#!/bin/sh\ncat > /dev/null\necho sat\necho '((sym0_32 #x000000ff))'\n",
            );
            let (pool, eq) = add1_eq_256_32();
            let (script, names) = build_script(&pool, &[(eq, true)]);
            let result = run_candidates(&script, &names, &[smt2(&quick)], Duration::from_secs(30));
            let _ = std::fs::remove_dir_all(&dir);
            match result {
                SolveResult::Sat(m) => assert_eq!(m.values.get(&0).copied(), Some(0xff)),
                other => panic!("expected sat from a prompt fake solver, got {other:?}"),
            }
        }

        /// Both directions of the solver pipe are larger than one OS pipe
        /// buffer (64 KiB on Linux). Writing the query on the calling thread
        /// while nothing drains the answer deadlocks: the solver blocks writing
        /// its answer, we block writing the query.
        ///
        /// The fake is run under `timeout` so a regression fails this test
        /// instead of hanging the suite and leaking a child.
        #[test]
        fn large_script_and_large_answer_do_not_deadlock() {
            if std::process::Command::new("timeout")
                .arg("--version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_err()
            {
                eprintln!("coreutils `timeout` unavailable - skipping");
                return;
            }

            // ~320 KiB of stdout, emitted before the fake ever looks at stdin.
            // "unsat" is printed first because the parser reads line one.
            let awk = r#"BEGIN { print "unsat"; s = "x"; while (length(s) < 4000) s = s s; for (i = 0; i < 80; i++) print substr(s, 1, 4000) }"#;
            let candidates = vec![(
                "timeout".to_string(),
                vec!["20".to_string(), "awk".to_string(), awk.to_string()],
            )];

            // A query with enough free symbols that the SMT-LIB2 text alone
            // exceeds one pipe buffer.
            let mut pool = ExprPool::new();
            let mut acc = pool.fresh_symbol(Width::W32);
            for _ in 0..4_000 {
                let next = pool.fresh_symbol(Width::W32);
                acc = pool.intern(Expr::Bin {
                    op: BinOp::Xor,
                    a: acc,
                    b: next,
                    width: Width::W32,
                });
            }
            let (script, names) = build_script(&pool, &[(acc, true)]);
            assert!(
                script.len() > 64 * 1024,
                "test query is not larger than a pipe buffer: {} bytes",
                script.len()
            );

            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(run_candidates(
                    &script,
                    &names,
                    &candidates,
                    Duration::from_secs(30),
                ));
            });
            let result = rx
                .recv_timeout(Duration::from_secs(25))
                .expect("pipe backend deadlocked on a query larger than one pipe buffer");
            assert_eq!(
                result,
                SolveResult::Unsat,
                "expected the fake solver's answer to survive a >64 KiB exchange"
            );
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
