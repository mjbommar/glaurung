//! Semantic tests of the equivalence checker.
//!
//! The checker's two failure modes are opposite and both silent: calling a
//! defect "equivalent", and calling a legitimate rewrite "different". Every test
//! here pins one of the two, and the corpus test at the end pins the second one
//! over the whole set of fixture functions the lowering covers, because a false
//! "different" is the failure that would make this an unusable oracle.

use crate::csource::lower::{lower_named_function, LoweredFunction};
use crate::symbolic::solver::{solve, SolveResult};

use super::{check_lowered, Bounds, DecidedBy, Unknown, Verdict};

/// Lower `text`'s function `name`, or panic with the refusal.
fn lower(text: &str, name: &str) -> LoweredFunction {
    match lower_named_function(text, name) {
        Ok(f) => f,
        Err(e) => panic!("{name} did not lower: {e}"),
    }
}

/// Whether a solver backend can answer at all. Without one every query is
/// `NoSolver`, and a test that asserted a verdict would be asserting nothing.
fn have_solver() -> bool {
    let mut pool = crate::symbolic::expr::ExprPool::new();
    let one = pool.constant(crate::ir::types::Width::W1, 1);
    !matches!(solve(&pool, &[(one, true)]), SolveResult::NoSolver)
}

/// Check two C texts' function `name` against each other.
fn compare(left: &str, right: &str, name: &str) -> super::EquivReport {
    check_lowered(&lower(left, name), &lower(right, name), Bounds::default())
}

#[test]
fn a_function_is_equivalent_to_itself() {
    if !have_solver() {
        eprintln!("SKIP: no SMT solver available -- this test asserted nothing");
        return;
    }
    let text = "int clamp(int a, int b) { if (a < b) return b; return a; }";
    let report = compare(text, text, "clamp");
    assert_eq!(report.verdict, Verdict::Equivalent, "{report:?}");
    assert_eq!(report.decided_by, DecidedBy::Solver);
}

#[test]
fn a_flipped_relational_operator_is_different_with_a_reproduced_witness() {
    let report = compare(
        "int lt(int a, int b) { if (a < b) return 1; return 0; }",
        "int lt(int a, int b) { if (a >= b) return 1; return 0; }",
        "lt",
    );
    assert_eq!(report.verdict, Verdict::Different, "{report:?}");
    let witness = report.witness.expect("a difference carries a witness");
    assert_ne!(witness.left, witness.right);
    // The probes alone separate this one: no solver is needed, and none is
    // asked for.
    assert_eq!(report.decided_by, DecidedBy::Probes);
}

#[test]
fn a_control_flow_rewrite_that_preserves_meaning_is_equivalent() {
    if !have_solver() {
        eprintln!("SKIP: no SMT solver available -- this test asserted nothing");
        return;
    }
    // The same function as a branch and as a conditional expression. Every
    // structural metric this project has sees two different graphs.
    let report = compare(
        "int pick(int a, int b) { if (a > b) { return a; } else { return b; } }",
        "int pick(int a, int b) { return a > b ? a : b; }",
        "pick",
    );
    assert_eq!(report.verdict, Verdict::Equivalent, "{report:?}");
}

#[test]
fn de_morgan_over_short_circuit_operators_is_equivalent() {
    if !have_solver() {
        eprintln!("SKIP: no SMT solver available -- this test asserted nothing");
        return;
    }
    let report = compare(
        "int both(int a, int b) { if (a && b) return 7; return -1; }",
        "int both(int a, int b) { if (!(!(a) || !(b))) return 7; return -1; }",
        "both",
    );
    assert_eq!(report.verdict, Verdict::Equivalent, "{report:?}");
}

#[test]
fn an_off_by_one_that_only_shows_at_the_boundary_is_still_found() {
    // `<` and `<=` agree everywhere except a == b; the probe set contains
    // all-equal vectors, so this is separated concretely rather than by the
    // solver. If the probe set ever loses its all-equal vectors, this test is
    // what notices.
    let report = compare(
        "int le(int a, int b) { if (a <= b) return 1; return 0; }",
        "int le(int a, int b) { if (a < b) return 1; return 0; }",
        "le",
    );
    assert_eq!(report.verdict, Verdict::Different, "{report:?}");
    let witness = report.witness.expect("a difference carries a witness");
    assert_eq!(witness.args[0], witness.args[1], "{witness:?}");
}

#[test]
fn a_loop_whose_trip_count_the_bound_covers_reaches_a_real_verdict() {
    if !have_solver() {
        eprintln!("SKIP: no SMT solver available -- this test asserted nothing");
        return;
    }
    // A concrete trip count never forks at all: the loop condition folds, so
    // both sides are a single path and there is nothing for the bound to cut.
    let report = compare(
        "int five(int a) { int i = 0; int s = 0; while (i < 5) { s = s + a; i = i + 1; } return s; }",
        "int five(int a) { int s = 0; int i = 5; while (i > 0) { s = s + a; i = i - 1; } return s; }",
        "five",
    );
    assert_eq!(report.verdict, Verdict::Equivalent, "{report:?}");
    assert_eq!(report.stats.complete_paths, (1, 1), "{report:?}");
    assert_eq!(report.stats.cut_paths, (0, 0), "{report:?}");
}

#[test]
fn a_cut_path_whose_guard_is_unsatisfiable_does_not_block_a_verdict() {
    if !have_solver() {
        eprintln!("SKIP: no SMT solver available -- this test asserted nothing");
        return;
    }
    // The trip count is symbolic, so the enumerator forks on every iteration and
    // the unroll bound eventually cuts one path. But an earlier test has already
    // constrained `n <= 3`, so the cut path's guard is unsatisfiable and the
    // completed paths still cover every input. This is the case the module docs
    // claim a coverage query recovers; without that second query the verdict
    // here would be `PartialCoverage` and the checker would abstain on every
    // bounded loop it meets.
    let report = compare(
        "int f(int n) { int i = 0; int s = 0; if (n > 3) return -1;          while (i < n) { s = s + 1; i = i + 1; } return s; }",
        "int f(int n) { if (n > 3) return -1; if (n < 0) return 0; return n; }",
        "f",
    );
    assert!(
        report.stats.cut_paths.0 > 0,
        "the unroll bound should have cut the past-the-end path: {report:?}"
    );
    assert_eq!(report.verdict, Verdict::Equivalent, "{report:?}");
    assert_eq!(
        report.stats.solves, 2,
        "one miter query and one coverage query"
    );
}

#[test]
fn a_loop_over_an_unconstrained_input_abstains_rather_than_claiming_equivalence() {
    if !have_solver() {
        eprintln!("SKIP: no SMT solver available -- this test asserted nothing");
        return;
    }
    // The trip count is the input, so no finite unrolling covers the input
    // space. Two genuinely equal implementations must NOT come back
    // "equivalent": the honest answer is that the bound did not reach it.
    let text = "int sum(int n) { int i = 0; int s = 0; while (i < n) { s = s + i; i = i + 1; } return s; }";
    let report = compare(text, text, "sum");
    assert_eq!(
        report.verdict,
        Verdict::Unknown(Unknown::PartialCoverage),
        "{report:?}"
    );
}

#[test]
fn a_void_function_has_no_observable_and_says_so() {
    let report = compare(
        "void nothing(int a) { int b = a + 1; }",
        "void nothing(int a) { int b = a - 1; }",
        "nothing",
    );
    assert_eq!(
        report.verdict,
        Verdict::Unknown(Unknown::NoObservableResult),
        "{report:?}"
    );
    assert_eq!(report.decided_by, DecidedBy::Contract);
}

#[test]
fn a_witness_is_an_input_the_declared_parameter_type_can_hold() {
    // `unsigned char` cannot hold 0x1ff. A symbol minted at 64 bits would let
    // the solver produce one, and the resulting "counterexample" would be
    // unreachable from any caller.
    let report = compare(
        "int wide(unsigned char a) { if (a > 200) return 1; return 0; }",
        "int wide(unsigned char a) { if (a > 199) return 1; return 0; }",
        "wide",
    );
    assert_eq!(report.verdict, Verdict::Different, "{report:?}");
    let witness = report.witness.expect("a difference carries a witness");
    assert!(witness.args[0] <= 0xff, "{witness:?}");
}

#[test]
fn the_bounds_are_carried_with_every_verdict() {
    let report = compare(
        "int one(void) { return 1; }",
        "int one(void) { return 2; }",
        "one",
    );
    assert_eq!(report.bounds, Bounds::default());
    assert!(report.bounds.max_block_visits > 0);
    assert!(report.bounds.max_paths > 0);
}

#[test]
fn a_re_run_gives_the_same_answer() {
    if !have_solver() {
        eprintln!("SKIP: no SMT solver available -- this test asserted nothing");
        return;
    }
    let left = "int f(int a, int b) { if (a < b) { return a * 2; } return b + a; }";
    let right = "int f(int a, int b) { return a < b ? a + a : a + b; }";
    let first = compare(left, right, "f");
    let second = compare(left, right, "f");
    assert_eq!(first, second);
}

#[test]
fn a_probe_value_is_reduced_to_what_the_declared_type_can_hold() {
    use crate::ir::types::Width;

    use super::InputSlot;

    let signed_char = InputSlot {
        reg: "rdi".to_string(),
        width: Width::W8,
        signed: true,
    };
    let unsigned_char = InputSlot {
        reg: "rdi".to_string(),
        width: Width::W8,
        signed: false,
    };
    let signed_int = InputSlot {
        reg: "rdi".to_string(),
        width: Width::W32,
        signed: true,
    };
    // 0xff is -1 as a `signed char` and 255 as an `unsigned char`; the 64-bit
    // form a caller passes differs accordingly.
    assert_eq!(signed_char.canonicalize(0xff), u64::MAX);
    assert_eq!(unsigned_char.canonicalize(0xff), 0xff);
    // Anything above the declared width is not part of the value.
    assert_eq!(unsigned_char.canonicalize(0xdead_beef), 0xef);
    assert_eq!(
        signed_int.canonicalize(0x0000_0000_8000_0000),
        0xffff_ffff_8000_0000
    );
    assert_eq!(signed_int.canonicalize(0x1234_5678_0000_0001), 1);
}

#[test]
fn an_input_symbol_is_minted_at_the_declared_width() {
    use crate::ir::types::Width;

    use super::{miter::seed_inputs, InputSlot, IoSpec};

    let io = IoSpec {
        inputs: vec![
            InputSlot {
                reg: "rdi".to_string(),
                width: Width::W8,
                signed: false,
            },
            InputSlot {
                reg: "rsi".to_string(),
                width: Width::W32,
                signed: true,
            },
        ],
        result_reg: "rax".to_string(),
        result_width: Some(Width::W32),
    };
    let mut sym = crate::symbolic::Symbolic::new();
    let (symbols, seeds) = seed_inputs(&mut sym, &io);
    assert_eq!(symbols.len(), 2);
    // An `unsigned char` is an 8-bit symbol widened by zero extension, and an
    // `int` a 32-bit symbol widened by sign extension. A symbol minted at 64
    // bits would render as a bare `sym0_64` and admit inputs no caller can pass.
    assert_eq!(sym.render(seeds[0].1), "((_ zero_extend 56) sym0_8)");
    assert_eq!(sym.render(seeds[1].1), "((_ sign_extend 32) sym1_32)");
}

#[test]
fn the_condition_tree_bound_is_what_limits_a_memory_carried_loop_counter() {
    use crate::ir::types::VReg;

    use super::explore::{explore, Cut};
    use super::{miter::seed_inputs, Bounds, IoSpec};

    // A counter that lives in a frame slot: `src/exec/memory.rs` rebuilds the
    // slot as a `Concat` of four `Extract`s of what was stored, so the
    // counter's expression tree multiplies by four every iteration while its
    // DAG grows by a handful of nodes. `Bounds::max_block_visits` is 12 here
    // and never gets to fire; the tree bound is what actually decides how far
    // the loop unrolls, which is why it is a recorded bound and not a constant.
    let f = lower(
        "unsigned int count(unsigned int n) { unsigned int i = 0; unsigned int s = 0; \
         while (i < n) { s = s + i; i = i + 1; } return s; }",
        "count",
    );
    let io = IoSpec::of_lowered(&f).expect("io");

    let explore_with = |cap: u64| {
        let bounds = Bounds {
            max_condition_tree_nodes: cap,
            ..Bounds::default()
        };
        let mut sym = crate::symbolic::Symbolic::new();
        let (_symbols, seeds) = seed_inputs(&mut sym, &io);
        let reg = VReg::phys(io.result_reg.clone());
        let (_sym, exploration) = explore(&f.func, sym, &seeds, &reg, &bounds);
        exploration
    };

    let tight = explore_with(64);
    let loose = explore_with(200_000);
    assert!(
        tight.complete.len() < loose.complete.len(),
        "a tighter tree bound must reach fewer returns: {} vs {}",
        tight.complete.len(),
        loose.complete.len()
    );
    assert!(
        tight
            .cuts
            .iter()
            .any(|cut| matches!(cut, Cut::ExpressionBound(_))),
        "the tight bound should cut on the condition tree, not something else: {:?}",
        tight.cuts
    );
}
