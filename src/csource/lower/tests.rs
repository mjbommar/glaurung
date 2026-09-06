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
    // Pointer parameters, dereference and now arithmetic all lower --- see
    // `pointer_arithmetic_scales_by_the_pointee_width`. What remains refused is
    // listed here, each by the name it refuses under.
    //
    // Pointer-to-pointer: `Local::pointee` is one level deep,
    // and treating `**p` as `*p` would read the wrong bytes.
    let err = lower_named_function("int f(int **p) { return **p; }", "f")
        .expect_err("pointer-to-pointer is not modelled");
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

/// A shift count at or above the promoted operand width.
///
/// C leaves this undefined, so unlike every other test here there is no "C's
/// value" to work out by hand. Every machine this lowering targets defines it
/// the same way --- x86 and ARM both take the count modulo the operand width
/// --- and the numbers below are what a gcc 15.2.0 binary prints for these
/// exact calls, identically at `-O0` and `-O1`, with the count passed through a
/// `volatile` so the shift is a real runtime instruction and not a folded
/// constant.
///
/// This is the one place where evaluating on 64-bit temporaries stops being
/// transparent. `Builder::binop` emits width-less ops and `Builder::normalize`
/// truncates afterwards, which is exactly right for add, sub and mul because
/// their low bits do not depend on the evaluation width. A shift's do: the
/// count is masked against the width the shift executes at. Unmasked, `1u << 32`
/// is 2^32 evaluated at 64 bits and truncates to 0, where the hardware masks the
/// count to 0 and yields 1.
#[test]
fn a_shift_count_at_the_operand_width_wraps_the_way_the_hardware_does() {
    let shl = lower(
        "unsigned int shl(unsigned int v, int c) { return v << c; }",
        "shl",
    );
    assert_eq!(call(&shl, &[1, 32]), 1, "1u << 32 masks the count to 0");
    assert_eq!(call(&shl, &[1, 33]), 2, "1u << 33 masks the count to 1");

    let shr = lower(
        "unsigned int shr(unsigned int v, int c) { return v >> c; }",
        "shr",
    );
    assert_eq!(call(&shr, &[0xdead_beef, 32]), 0xdead_beef);

    let sar = lower("int sar(int v, int c) { return v >> c; }", "sar");
    // -8 >> 0 is -8, whose masked 32-bit result is 0xfffffff8.
    assert_eq!(call(&sar, &[(-8i64) as u64, 32]), 0xffff_fff8);

    // The 64-bit control: a `long` shift already evaluates at its own width, so
    // this case passes with or without the mask and pins that it stays correct.
    let wide = lower(
        "unsigned long wide(unsigned long v, int c) { return v << c; }",
        "wide",
    );
    assert_eq!(call(&wide, &[1, 64]), 1);
}

#[test]
fn a_pointer_to_a_local_round_trips_through_memory() {
    // The whole point of admitting pointers: `&x` puts a real frame address in
    // a register, `*p` loads through it, and the width comes from the pointee
    // rather than a guess. Run on the real interpreter, so this is the load
    // actually executing rather than the lowering merely compiling.
    //
    // Written so the C itself supplies the value, because there is no helper
    // to seed memory from the outside and inventing one to test this would put
    // the test's own arithmetic between the lowering and the answer.
    let f = lower("int f(int a) { int x = a; int *p = &x; return *p; }", "f");
    assert_eq!(call(&f, &[7]), 7);
    assert_eq!(call(&f, &[(-3i64) as u64]), (-3i64) as u64 & 0xffff_ffff);
}

#[test]
fn a_pointee_width_decides_how_many_bytes_a_dereference_reads() {
    // Taking the width from the pointee rather than the pointer is why
    // `Val::pointee` exists. A `char` local holds one byte, so dereferencing a
    // `char *` to it reads one; an `int` local dereferenced through an `int *`
    // reads four.
    //
    // Declared rather than cast: `(char *)&x` is a cast to a pointer type,
    // which this lowering still refuses, and writing the test with one would
    // be testing a construct that does not exist yet.
    let wide = lower("int f(int a) { int x = a; int *p = &x; return *p; }", "f");
    let narrow = lower(
        "int f(int a) { char c = (char)a; char *p = &c; return *p; }",
        "f",
    );
    assert_eq!(call(&wide, &[0x44332211]), 0x44332211);
    // 0x11 fits in a signed char, so the sign extension is a no-op here.
    assert_eq!(call(&narrow, &[0x44332211]), 0x11);
}

#[test]
fn an_object_like_macro_constant_resolves() {
    // No preprocessor, so `#define N 8` leaves `N` in the tree looking exactly
    // like a global. Measured over the corpus, 533 of 962 unresolved names are
    // this shape against 54 real file-scope variables, which is why it is
    // worth resolving and a memory model is not the first thing to build.
    let f = lower("#define N 8\nint f(int a) { return a * N; }", "f");
    assert_eq!(call(&f, &[3]), 24);
}

#[test]
fn a_macro_constant_takes_its_base_and_sign() {
    let hex = lower("#define M 0x10\nint f(void) { return M; }", "f");
    assert_eq!(call(&hex, &[]), 0x10);
    let suffixed = lower("#define M 12u\nint f(void) { return M; }", "f");
    assert_eq!(call(&suffixed, &[]), 12);
    let negative = lower("#define M -5\nint f(void) { return M; }", "f");
    assert_eq!(call(&negative, &[]), (-5i64) as u64 & 0xffff_ffff);
}

#[test]
fn a_trailing_comment_does_not_become_part_of_the_value() {
    // The fixture corpus writes `#define N 8   /* ... */` constantly.
    let f = lower(
        "#define N 8   /* eight of them */\nint f(void) { return N; }",
        "f",
    );
    assert_eq!(call(&f, &[]), 8);
}

#[test]
fn a_macro_whose_body_is_not_an_integer_is_still_refused() {
    // `#define STRIDE (N * 2)` is an expression, and evaluating one here would
    // be a second, worse parser. Refusing by name is the honest answer.
    let err = lower_named_function(
        "#define N 8\n#define STRIDE (N * 2)\nint f(void) { return STRIDE; }",
        "f",
    )
    .expect_err("an expression-bodied macro is not a constant");
    assert!(err.what.contains("STRIDE"), "{err}");
}

#[test]
fn a_function_like_macro_is_not_mistaken_for_a_constant() {
    let err = lower_named_function(
        "#define TWICE(x) ((x) * 2)\nint f(int a) { return TWICE(a); }",
        "f",
    )
    .expect_err("a function-like macro is not an object-like constant");
    // It reads as a call, which is refused for its own reason.
    assert!(!err.what.contains("TWICE(x)"), "{err}");
}

#[test]
fn a_local_wins_over_a_macro_of_the_same_name() {
    // Safe rather than arbitrary: C expands macros before scoping, so a file
    // that both defines `N` and declares a local `N` does not compile. The
    // order is asserted so a future change cannot silently invert it.
    let f = lower(
        "#define VALUE 99\nint f(int a) { int VALUE = a; return VALUE; }",
        "f",
    );
    assert_eq!(call(&f, &[7]), 7);
}

// ---------------------------------------------------------------------------
// Arrays, subscripts and pointer arithmetic.
//
// Every expected value below was produced by `gcc -O0` *and* `gcc -O1` on the
// equivalent C, per `CLAUDE.md`: "to decide what C means, compile it". Deriving
// them from a second reading of the same rules would only prove two of my
// readings agree.
// ---------------------------------------------------------------------------

#[test]
fn an_array_element_is_addressed_by_its_index() {
    let f = lower(
        "int pick(int i) { int a[4]; a[0] = 10; a[1] = 20; a[2] = 30; a[3] = 40; return a[i]; }",
        "pick",
    );
    assert_eq!(call(&f, &[0]), 10);
    assert_eq!(call(&f, &[2]), 30);
    assert_eq!(call(&f, &[3]), 40);
}

#[test]
fn a_braced_initializer_fills_the_front_and_zeroes_the_rest() {
    // gcc: `int b[4] = {7, 8}` gives 7 8 0 0. The zeroes are C's guarantee, and
    // the lowering emits them rather than trusting the frame to be clear.
    let f = lower(
        "int pick(int i) { int b[4] = {7, 8}; return b[i]; }",
        "pick",
    );
    assert_eq!(call(&f, &[0]), 7);
    assert_eq!(call(&f, &[1]), 8);
    assert_eq!(call(&f, &[2]), 0);
    assert_eq!(call(&f, &[3]), 0);
}

#[test]
fn pointer_arithmetic_scales_by_the_pointee_width() {
    // The regression this whole capability was blocked on: `p += 2` on an
    // `int *` advances eight bytes, not two.
    let ints = lower(
        "int walk(void) { int a[4] = {1, 2, 3, 4}; int *p = a; p += 2; return *p; }",
        "walk",
    );
    assert_eq!(call(&ints, &[]), 3);
    // The same source shape on a `char *` advances two bytes, which is the
    // point: one rule, two widths. gcc says `*q` is 3.
    let chars = lower(
        "int walk(void) { char c[4] = {1, 2, 3, 4}; char *q = c; q += 2; return *q; }",
        "walk",
    );
    assert_eq!(call(&chars, &[]), 3);
}

#[test]
fn an_increment_of_a_pointer_scales_too() {
    let f = lower(
        "int second(void) { int a[3] = {11, 22, 33}; int *p = a; p++; return *p; }",
        "second",
    );
    assert_eq!(call(&f, &[]), 22);
    // `*++p` must still see a pointer, or the dereference has no width.
    let prefixed = lower(
        "int third(void) { int a[3] = {11, 22, 33}; int *p = a; ++p; return *++p; }",
        "third",
    );
    assert_eq!(call(&prefixed, &[]), 33);
}

#[test]
fn a_negative_index_walks_backwards() {
    // gcc: with `p = a + 7` over `a[k] = k * 10`, `p[-1]` is 60. The index is
    // sign-extended before it is scaled --- scaling the unsigned reading of -1
    // would land 16GB away.
    let f = lower(
        "int back(void) { int a[8]; int k = 0; while (k < 8) { a[k] = k * 10; k++; } \
         int *p = a + 7; return p[-1]; }",
        "back",
    );
    assert_eq!(call(&f, &[]), 60);
}

#[test]
fn pointer_difference_counts_elements_and_keeps_its_sign() {
    // gcc: `p - a` is 7 and `a - p` is -7. The second is why the difference
    // goes through signed division: an unsigned divide turns -28 bytes into an
    // enormous positive count.
    let forward = lower(
        "long gap(void) { int a[8]; int *p = a + 7; return p - a; }",
        "gap",
    );
    assert_eq!(call(&forward, &[]), 7);
    let backward = lower(
        "long gap(void) { int a[8]; int *p = a + 7; return a - p; }",
        "gap",
    );
    assert_eq!(call(&backward, &[]), (-7i64) as u64);
}

#[test]
fn a_subscript_is_addition_so_it_commutes() {
    // `2[a]` is legal C and gcc agrees it is `a[2]`. It is here because it
    // proves the lowering implements the *definition* rather than a special
    // case for an array on the left.
    let f = lower(
        "int odd(void) { int a[3] = {5, 6, 7}; return 2[a]; }",
        "odd",
    );
    assert_eq!(call(&f, &[]), 7);
}

#[test]
fn an_element_is_writable_through_a_subscript_and_through_a_pointer() {
    let subscript = lower(
        "int put(int v) { int a[3] = {0, 0, 0}; a[1] = v; return a[1]; }",
        "put",
    );
    assert_eq!(call(&subscript, &[42]), 42);
    let indirect = lower(
        "int put(int v) { int a[3] = {0, 0, 0}; int *p = a + 1; *p = v; return a[1]; }",
        "put",
    );
    assert_eq!(call(&indirect, &[42]), 42);
}

#[test]
fn a_narrow_element_is_truncated_by_the_store_not_by_the_load() {
    // The store width comes from the address value's pointee. A `char` array
    // written with 0x1ff must read back 0xff sign-extended, i.e. -1.
    let f = lower(
        "int narrow(int v) { char c[2] = {0, 0}; c[0] = v; return c[0]; }",
        "narrow",
    );
    assert_eq!(call(&f, &[0x1ff]), (-1i32) as u32 as u64);
}

#[test]
fn incrementing_an_element_reads_and_writes_the_same_cell() {
    let f = lower(
        "int bump(int i) { int a[3] = {1, 2, 3}; a[i]++; return a[i]; }",
        "bump",
    );
    assert_eq!(call(&f, &[1]), 3);
    let prefix = lower(
        "int bump(int i) { int a[3] = {1, 2, 3}; return ++a[i]; }",
        "bump",
    );
    assert_eq!(call(&prefix, &[2]), 4);
}

#[test]
fn a_compound_assignment_through_a_subscript_evaluates_the_index_once() {
    // gcc, at -O0 and -O1: `a[i++] += 5` leaves `a[2]` at 25 and `i` at 3. If
    // the address were computed twice, `i` would reach 4 and the read and the
    // write would land in different cells.
    let f = lower(
        "int once(void) { int a[8]; int k = 0; while (k < 8) { a[k] = k * 10; k++; } \
         int i = 2; a[i++] += 5; return a[2] * 100 + i; }",
        "once",
    );
    assert_eq!(call(&f, &[]), 2503);
}

#[test]
fn the_address_of_an_element_is_the_array_plus_the_index() {
    // gcc: `&a[2] - a` is 2. `&a[i]` is the subscript's address computation
    // with the load left off, which is why it needs no code of its own.
    let f = lower("long where(int i) { int a[8]; return &a[i] - a; }", "where");
    assert_eq!(call(&f, &[5]), 5);
}

#[test]
fn a_macro_may_give_the_array_its_extent() {
    // `#define N 8` then `int a[N]` is the shape the fixture corpus writes, and
    // the extent has to come from the same macro table the expressions use.
    let f = lower(
        "#define N 4\nint last(void) { int a[N]; a[N - 1] = 9; return a[3]; }",
        "last",
    );
    assert_eq!(call(&f, &[]), 9);
}

#[test]
fn an_array_without_a_constant_extent_is_refused() {
    // A variable-length array's storage is not a fixed frame slot, so it is a
    // different object rather than a bigger one.
    let err = lower_named_function("int f(int n) { int a[n]; a[0] = 1; return a[0]; }", "f")
        .expect_err("a variable-length array is not a frame slot");
    assert!(err.what.contains("extent"), "{err}");
}

#[test]
fn a_multi_dimensional_array_is_refused() {
    // `Local::pointee` is one `IntType` deep, so there is nowhere to record a
    // row stride. Refusing is the difference between no answer and a wrong one.
    let err = lower_named_function("int f(void) { int m[2][3]; return m[1][2]; }", "f")
        .expect_err("a row stride cannot be recorded");
    assert!(err.what.contains("multi-dimensional"), "{err}");
}

#[test]
fn an_array_name_is_not_a_modifiable_lvalue() {
    let err = lower_named_function(
        "int f(void) { int a[2]; int b[2]; a = b; return a[0]; }",
        "f",
    )
    .expect_err("C does not allow assigning to an array name");
    assert!(err.what.contains("array name"), "{err}");
}

#[test]
fn the_construct_the_refusal_test_used_to_name_now_lowers() {
    // `*(p + 1)` was the example in
    // `an_unlowerable_construct_is_refused_by_name_rather_than_approximated`
    // of a named refusal. It is kept as a test of the thing itself so the
    // refusal list cannot quietly grow it back.
    let f = lower(
        "int at(int i) { int a[4] = {2, 4, 6, 8}; int *p = a; return *(p + i); }",
        "at",
    );
    assert_eq!(call(&f, &[0]), 2);
    assert_eq!(call(&f, &[3]), 8);
}

// ---------------------------------------------------------------------------
// Calls, substituted rather than emitted.
//
// Expected values from `gcc -O0` and `-O1` on the equivalent C, as above.
// ---------------------------------------------------------------------------

#[test]
fn a_call_to_a_function_defined_here_is_substituted() {
    let f = lower(
        "int g(int a) { return a + 1; } int f(int x) { return g(x); }",
        "f",
    );
    assert_eq!(call(&f, &[3]), 4);
}

#[test]
fn a_return_inside_an_inlined_body_does_not_end_the_caller() {
    // The whole hazard of substitution: `Op::Return` in the callee would end
    // `f` as well, and the `+ 7` would never run. gcc says 17.
    let f = lower(
        "int early(int a) { if (a > 0) return 10; return 20; } \
         int f(int a) { return early(a) + 7; }",
        "f",
    );
    assert_eq!(call(&f, &[1]), 17);
    assert_eq!(call(&f, &[0]), 27);
}

#[test]
fn a_callee_cannot_see_the_callers_locals() {
    // `hidden` is a local of the caller, not a global. A scope stack that
    // leaked would silently make this compile-and-run instead of refusing.
    let err = lower_named_function(
        "int g(int a) { return a + hidden; } int f(int x) { int hidden = 5; return g(x); }",
        "f",
    )
    .expect_err("a callee does not see the caller's frame");
    assert!(err.what.contains("hidden"), "{err}");
}

#[test]
fn a_break_in_a_callee_cannot_target_the_callers_loop() {
    let err = lower_named_function(
        "int g(int a) { break; return a; } \
         int f(int n) { int s = 0; while (n > 0) { s += g(n); n--; } return s; }",
        "f",
    )
    .expect_err("the callee has no enclosing loop of its own");
    assert!(err.what.contains("break"), "{err}");
}

#[test]
fn an_argument_is_narrowed_to_the_parameters_declared_type() {
    // gcc: `narrow((char) 200)` is -56, because 200 does not fit in a signed
    // `char`. The truncation belongs to the call, not to the caller.
    let f = lower(
        "char narrow(char c) { return c; } int f(int v) { return narrow(v); }",
        "f",
    );
    assert_eq!(call(&f, &[200]), (-56i32) as u32 as u64);
}

#[test]
fn a_callee_writes_through_a_pointer_into_the_callers_frame() {
    // gcc: 5. The callee's parameter is the caller's frame address, so the
    // store lands in the caller's local --- which is the whole reason
    // substitution has to keep one flat address space.
    let f = lower(
        "void setit(int *p) { *p = 5; } int f(void) { int x = 0; setit(&x); return x; }",
        "f",
    );
    assert_eq!(call(&f, &[]), 5);
}

#[test]
fn two_calls_to_one_function_get_two_frames() {
    // gcc: `g(2) + g(20)` is 3 + 21 = 24. One shared frame would make the
    // second call overwrite the first's parameter before it was read.
    let f = lower(
        "int g(int a) { return a + 1; } int f(int a) { return g(a) + g(a * 10); }",
        "f",
    );
    assert_eq!(call(&f, &[2]), 24);
}

#[test]
fn a_call_inside_a_loop_runs_once_per_iteration() {
    // gcc: 0+1 + 1+1 + 2+1 + 3+1 = 10. One set of frame slots is reused across
    // iterations, which is what a real frame does.
    let f = lower(
        "int g(int a) { return a + 1; } \
         int f(int n) { int s = 0; for (int i = 0; i < n; i++) s += g(i); return s; }",
        "f",
    );
    assert_eq!(call(&f, &[4]), 10);
}

#[test]
fn a_recursive_call_is_refused_by_name() {
    // Substitution is not a fixpoint, so this is a refusal and not a depth
    // cut. `csource::dataflow::interproc`'s summaries are the mechanism that
    // does terminate on a cycle.
    let err = lower_named_function(
        "int fact(int n) { if (n < 2) return 1; return n * fact(n - 1); }",
        "fact",
    )
    .expect_err("a body cannot be substituted into itself");
    assert!(err.what.contains("recursive"), "{err}");
}

#[test]
fn mutual_recursion_is_refused_through_the_cycle() {
    let err = lower_named_function(
        "int odd(int n); int even(int n) { return n == 0 ? 1 : odd(n - 1); } \
         int odd(int n) { return n == 0 ? 0 : even(n - 1); }",
        "even",
    )
    .expect_err("a cycle of any length is still a cycle");
    assert!(err.what.contains("recursive"), "{err}");
}

#[test]
fn an_arity_mismatch_is_refused_rather_than_padded() {
    let err = lower_named_function(
        "int g(int a, int b) { return a + b; } int f(int x) { return g(x); }",
        "f",
    )
    .expect_err("a missing argument has no value to pass");
    assert!(err.what.contains("arguments"), "{err}");
}

#[test]
fn a_callee_not_defined_in_this_file_is_refused_by_its_name() {
    // Naming the callee is what lets `call_census` rank them: `memcpy` needs a
    // model, `__builtin_expect` needs one line, and `UNLIKELY` is not a
    // function at all.
    let err = lower_named_function("int f(int n) { return __builtin_expect(n, 0); }", "f")
        .expect_err("there is no body to substitute");
    assert!(err.what.contains("__builtin_expect"), "{err}");
}

#[test]
fn a_cast_shaped_like_a_call_is_a_cast() {
    // `(uint8_t)(x)` and `f(x)` are the same shape to a parser with no type
    // table. This one has a type table.
    let f = lower("int f(int x) { return (unsigned char)(x + 1); }", "f");
    assert_eq!(call(&f, &[254]), 255);
    assert_eq!(call(&f, &[255]), 0);
}

#[test]
fn a_parenthesised_name_that_is_not_a_type_stays_a_call() {
    // The disambiguation must be conservative in this direction: turning a
    // real call into a cast would silently drop the callee.
    let f = lower(
        "int g(int a) { return a * 3; } int f(int x) { return (g)(x); }",
        "f",
    );
    assert_eq!(call(&f, &[5]), 15);
}

#[test]
fn a_local_shadowing_a_type_name_keeps_its_call() {
    // C lets an object shadow a typedef name. `(size_t)(x)` is then not a cast
    // at all, and resolving names against the scopes first is what says so.
    let err = lower_named_function("int f(int x) { int size_t = 2; return (size_t)(x); }", "f")
        .expect_err("a local is not callable");
    // The refusal names the callee rather than the shape, which is the more
    // useful of the two: `size_t` here is a variable being called.
    assert!(err.what.contains("`size_t`"), "{err}");
}
