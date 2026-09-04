//! Semantic tests of the lowering, run on the real interpreter.
//!
//! Each test lowers a C function, executes it under `crate::exec` and checks the
//! value. The expected values are C's, worked out by hand and written down ---
//! never computed by a second Rust translation of the same expression, which
//! would only prove two of my own readings agree.

use crate::csource::lower::differential::{run_with_args, STACK_POINTER};
use crate::csource::lower::{lower_named_function, LoweredFunction};
use crate::exec::Outcome;

const STEPS: u64 = 200_000;

/// Lower `text`'s function `name`, or panic with the refusal.
fn lower(text: &str, name: &str) -> LoweredFunction {
    match lower_named_function(text, name) {
        Ok(f) => f,
        Err(e) => panic!("{name} did not lower: {e}"),
    }
}

/// Run a lowered function and return its masked result, asserting it returned.
fn call(f: &LoweredFunction, args: &[u64]) -> u64 {
    let run = run_with_args(&f.func, args, f.result_width(), STACK_POINTER, STEPS);
    assert_eq!(
        run.outcome,
        Outcome::Returned,
        "{} did not return: {}",
        f.name,
        run.detail()
    );
    run.result.expect("a returned run has a result")
}

#[test]
fn integer_addition_wraps_at_the_declared_width() {
    let f = lower("int add(int a, int b) { return a + b; }", "add");
    assert_eq!(call(&f, &[2, 3]), 5);
    // INT32_MAX + 1 wraps to INT32_MIN; the masked 32-bit result is 0x80000000.
    assert_eq!(call(&f, &[0x7fff_ffff, 1]), 0x8000_0000);
    // (-1) + (-1) = -2, masked to 32 bits.
    assert_eq!(call(&f, &[u64::MAX, u64::MAX]), 0xffff_fffe);
    // The upper half of the argument register is not part of an `int`.
    assert_eq!(call(&f, &[0xdead_beef_0000_0002, 3]), 5);
}

#[test]
fn a_short_result_is_narrowed_before_it_is_returned() {
    let f = lower(
        "short narrow(int a) { short s = (short) a; return s; }",
        "narrow",
    );
    assert_eq!(f.result_width().expect("short").bits(), 16);
    assert_eq!(call(&f, &[0x1_2345]), 0x2345);
    assert_eq!(call(&f, &[0xffff_8000]), 0x8000);
}

#[test]
fn unsigned_and_signed_comparison_disagree_where_c_says_they_must() {
    let signed = lower("int lt(int a, int b) { return a < b; }", "lt");
    let unsigned = lower("int ltu(unsigned a, unsigned b) { return a < b; }", "ltu");
    // -1 < 1 signed; 0xffffffff < 1 is false unsigned. Same bits, both ways.
    assert_eq!(call(&signed, &[u64::MAX, 1]), 1);
    assert_eq!(call(&unsigned, &[0xffff_ffff, 1]), 0);
}

#[test]
fn signed_division_truncates_toward_zero_and_the_remainder_takes_the_dividends_sign() {
    let div = lower("int sdiv(int a, int b) { return a / b; }", "sdiv");
    let rem = lower("int srem(int a, int b) { return a % b; }", "srem");
    assert_eq!(call(&div, &[7, 2]), 3);
    // -7 / 2 is -3 in C (truncation), not -4 (floor).
    assert_eq!(call(&div, &[(-7i64) as u64, 2]), (-3i32) as u32 as u64);
    assert_eq!(call(&div, &[7, (-2i64) as u64]), (-3i32) as u32 as u64);
    assert_eq!(call(&div, &[(-7i64) as u64, (-2i64) as u64]), 3);
    assert_eq!(call(&rem, &[7, 2]), 1);
    assert_eq!(call(&rem, &[(-7i64) as u64, 2]), (-1i32) as u32 as u64);
    assert_eq!(call(&rem, &[7, (-2i64) as u64]), 1);
}

#[test]
fn unsigned_division_uses_the_domains_own_divide() {
    let f = lower("unsigned d(unsigned a, unsigned b) { return a / b; }", "d");
    assert_eq!(call(&f, &[0xffff_ffff, 2]), 0x7fff_ffff);
    assert_eq!(call(&f, &[7, 2]), 3);
}

#[test]
fn shifts_take_the_promoted_left_operands_type_not_the_common_type() {
    let arithmetic = lower("int sar(int a, int n) { return a >> n; }", "sar");
    let logical = lower("unsigned shr(unsigned a, int n) { return a >> n; }", "shr");
    // -8 >> 1 is -4: an arithmetic shift, because the left operand is signed.
    assert_eq!(
        call(&arithmetic, &[(-8i64) as u64, 1]),
        (-4i32) as u32 as u64
    );
    // The same bits shifted as `unsigned` are a logical shift.
    assert_eq!(call(&logical, &[0xffff_fff8, 1]), 0x7fff_fffc);
    let left = lower("int shl(int a, int n) { return a << n; }", "shl");
    assert_eq!(call(&left, &[1, 31]), 0x8000_0000);
}

#[test]
fn a_sixty_four_bit_right_shift_is_where_arithmetic_and_logical_actually_differ() {
    // At 32 bits the two are indistinguishable *in this representation*: a
    // canonical signed value is already sign-extended to 64, so a logical
    // 64-bit shift truncated back to 32 gives the arithmetic answer. Swapping
    // `Sar` for `Shr` therefore passed every 32-bit test. Only a 64-bit type
    // separates them, which is why this test exists and the 32-bit one is not
    // enough.
    let signed = lower("long sar(long a, int n) { return a >> n; }", "sar");
    let unsigned = lower(
        "unsigned long shr(unsigned long a, int n) { return a >> n; }",
        "shr",
    );
    assert_eq!(call(&signed, &[(-8i64) as u64, 1]), (-4i64) as u64);
    assert_eq!(call(&unsigned, &[(-8i64) as u64, 1]), 0x7fff_ffff_ffff_fffc);
}

#[test]
fn greater_than_is_the_same_comparison_with_its_operands_the_other_way_round() {
    let gt = lower("int gt(int a, int b) { return a > b; }", "gt");
    let ge = lower("int ge(int a, int b) { return a >= b; }", "ge");
    assert_eq!(call(&gt, &[3, 5]), 0);
    assert_eq!(call(&gt, &[5, 3]), 1);
    assert_eq!(call(&gt, &[5, 5]), 0);
    assert_eq!(call(&ge, &[5, 5]), 1);
    assert_eq!(call(&ge, &[3, 5]), 0);
}

#[test]
fn a_chain_of_short_circuit_operators_stops_at_the_first_decisive_operand() {
    // Three operands, so a two-operand-only implementation fails here.
    let and = lower("int f(int a, int b, int c) { return a && b && c; }", "f");
    assert_eq!(call(&and, &[1, 1, 1]), 1);
    assert_eq!(call(&and, &[1, 0, 1]), 0);
    assert_eq!(call(&and, &[0, 1, 1]), 0);
    let or = lower("int g(int a, int b, int c) { return a || b || c; }", "g");
    assert_eq!(call(&or, &[0, 0, 0]), 0);
    assert_eq!(call(&or, &[0, 0, 7]), 1);
    // `&&` binds tighter than `||`, so this is `a || (b && c)`.
    let mixed = lower("int h(int a, int b, int c) { return a || b && c; }", "h");
    assert_eq!(call(&mixed, &[0, 1, 0]), 0);
    assert_eq!(call(&mixed, &[1, 0, 0]), 1);
}

#[test]
fn short_circuit_operators_do_not_evaluate_the_right_operand() {
    // If `||` evaluated its right operand, `n / 0` would run. The domain
    // returns 0 for a divide by zero rather than trapping, so the observable
    // difference is in the *result*: a non-short-circuiting lowering of
    // `n == 0 || 100 / n > 3` returns 0 for n == 0.
    let f = lower(
        "int guard(int n) { return n == 0 || 100 / n > 3; }",
        "guard",
    );
    assert_eq!(call(&f, &[0]), 1);
    assert_eq!(call(&f, &[10]), 1);
    assert_eq!(call(&f, &[50]), 0);
    let and = lower("int both(int n) { return n != 0 && 100 / n > 3; }", "both");
    assert_eq!(call(&and, &[0]), 0);
    assert_eq!(call(&and, &[10]), 1);
}

#[test]
fn the_conditional_operator_converts_its_arms_to_their_common_type() {
    // `c ? -1 : 1u` has type `unsigned int`, so the then-arm's value is
    // 0xffffffff and `> 100` is an *unsigned* comparison that is true. A
    // lowering that gave the conditional its then-arm's type would compare
    // signed and answer 0.
    //
    // The comparison has to consume the conditional directly: assigning it to
    // an `unsigned` first re-converts the value and hides the mistake, which is
    // what an earlier version of this test did --- it passed with the type rule
    // deliberately broken.
    let f = lower("int pick(int c) { return (c ? -1 : 1u) > 100; }", "pick");
    assert_eq!(call(&f, &[1]), 1);
    assert_eq!(call(&f, &[0]), 0);
}

#[test]
fn a_while_loop_runs_its_body_the_declared_number_of_times() {
    let f = lower(
        "int total(int n) { int s = 0; int i = 0; while (i < n) { s += i; i++; } return s; }",
        "total",
    );
    assert_eq!(call(&f, &[0]), 0);
    assert_eq!(call(&f, &[1]), 0);
    assert_eq!(call(&f, &[5]), 10);
    assert_eq!(
        call(&f, &[(-3i64) as u64]),
        0,
        "a negative bound runs never"
    );
}

#[test]
fn a_do_while_loop_runs_its_body_at_least_once() {
    let f = lower(
        "int once(int n) { int s = 0; do { s += 1; n--; } while (n > 0); return s; }",
        "once",
    );
    assert_eq!(call(&f, &[0]), 1);
    assert_eq!(call(&f, &[3]), 3);
}

#[test]
fn for_loops_carry_break_and_continue_to_the_right_targets() {
    let f = lower(
        "int f(int n) { int s = 0; for (int i = 0; i < n; i++) { if (i == 3) continue; \
         if (i == 6) break; s += i; } return s; }",
        "f",
    );
    // i in 0..6 with 3 skipped and 6 breaking: 0+1+2+4+5 = 12.
    assert_eq!(call(&f, &[10]), 12);
    assert_eq!(call(&f, &[3]), 3);
}

#[test]
fn nested_loops_and_early_returns_reach_the_right_exit() {
    let f = lower(
        "int has_pair(int n, int target) { for (int i = 0; i < n; i++) \
         { for (int j = i + 1; j < n; j++) { if (i + j == target) return 1; } } return 0; }",
        "has_pair",
    );
    assert_eq!(call(&f, &[5, 7]), 1);
    assert_eq!(call(&f, &[5, 100]), 0);
    assert_eq!(call(&f, &[0, 0]), 0);
}

#[test]
fn an_inner_scope_shadows_and_the_outer_binding_comes_back() {
    let f = lower(
        "int shadow(int a) { int x = a; { int x = a + 10; a = x; } return a + x; }",
        "shadow",
    );
    // a becomes a+10, x is still the original a: (a+10) + a.
    assert_eq!(call(&f, &[5]), 20);
}

#[test]
fn post_and_pre_increment_differ_in_the_value_they_yield() {
    let post = lower("int p(int a) { int b = a++; return b * 100 + a; }", "p");
    let pre = lower("int q(int a) { int b = ++a; return b * 100 + a; }", "q");
    assert_eq!(call(&post, &[3]), 3 * 100 + 4);
    assert_eq!(call(&pre, &[3]), 4 * 100 + 4);
}

#[test]
fn character_and_unsigned_char_locals_keep_their_own_signedness() {
    let signed = lower("int s(int a) { char c = (char) a; return c; }", "s");
    let unsigned = lower(
        "int u(int a) { unsigned char c = (unsigned char) a; return c; }",
        "u",
    );
    assert_eq!(call(&signed, &[0xff]), (-1i32) as u32 as u64);
    assert_eq!(call(&unsigned, &[0xff]), 255);
}

#[test]
fn a_long_result_keeps_all_sixty_four_bits() {
    let f = lower(
        "long widen(int a) { long x = a; return x * 4294967296L; }",
        "widen",
    );
    assert_eq!(call(&f, &[3]), 3u64 << 32);
    assert_eq!(call(&f, &[(-1i64) as u64]), (-1i64 << 32) as u64);
}

#[test]
fn an_unlowerable_construct_is_refused_by_name_rather_than_approximated() {
    let err = lower_named_function("int f(int *p) { return *p; }", "f")
        .expect_err("a pointer parameter is not modelled");
    assert!(err.what.contains("pointer"), "{err}");
    let err = lower_named_function("double f(double x) { return x; }", "f")
        .expect_err("floating point is not modelled");
    assert!(err.what.contains("floating"), "{err}");
    let err = lower_named_function(
        "int f(int a) { switch (a) { case 1: return 1; } return 0; }",
        "f",
    )
    .expect_err("switch is not modelled");
    assert!(err.what.contains("switch"), "{err}");
    let err = lower_named_function("int g(void); int f(void) { return g(); }", "f")
        .expect_err("a call is not modelled");
    assert!(err.what.contains("call"), "{err}");
}

#[test]
fn a_deeply_nested_expression_lowers_without_touching_the_native_stack() {
    // The incident `roadmap.md` section 0 records: a recursive walk aborts the
    // process here rather than reporting a per-function failure.
    let depth = 4000;
    let text = format!(
        "int deep(int a) {{ return {}a{}; }}",
        "(".repeat(depth),
        ")".repeat(depth)
    );
    let f = lower(&text, "deep");
    assert_eq!(call(&f, &[7]), 7);
}
