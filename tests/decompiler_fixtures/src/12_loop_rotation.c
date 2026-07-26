/* 12_loop_rotation.c
 *
 * Loop SHAPE fixture. `03_loop_shapes.c` covers what a loop computes; this file
 * covers how the compiler lays one out, because the two disagree across
 * toolchains and our structurer was built against only one of them.
 *
 * gcc -O0 emits a bottom-tested loop: fall into the body, test at the bottom,
 * conditional branch back. clang -O0 emits a ROTATED loop: test at the top with
 * a conditional branch OUT, and an unconditional jump back at the bottom. We
 * structure the first correctly and the second wrongly — `loops.c:factorial` at
 * clang -O0 came out as
 *
 *     while ((n <= 1)) { ...; n = n - 1; goto L; }
 *     return f;
 *     L: ;
 *
 * with the machine's EXIT test used as the CONTINUE condition and the back-edge
 * jumping to a label placed after the return, so the body can never repeat. The
 * function returns the wrong value for every input.
 *
 * Every function here returns a value that differs if the loop runs the wrong
 * number of times, exits on the wrong polarity, or fails to iterate at all — a
 * decompiler that drops the back-edge returns the first iteration's value and is
 * caught. All parameters and returns are integer; deterministic; terminating;
 * every trip count is masked so no verdict depends on machine speed. No libc.
 *
 * Targets review #31 (clang rotated loops), and gives #13 (interval/SESE
 * structurer) something to be proven against.
 */
#include <stdint.h>

/* The exact shape that broke: a top-tested `while` whose body decrements. If the
 * back-edge is lost this returns 1 (the initial value) instead of n!. */
long factorial_while(int n) {
    long f = 1;
    int k = n & 15;                 /* bounded */
    while (k > 1) {
        f *= k;
        k--;
    }
    return f;
}

/* Same shape, opposite polarity: the test that continues is `<`, so an inverted
 * condition runs zero times instead of n. */
long count_up(int n) {
    long acc = 0;
    int i = 0;
    int lim = n & 15;
    while (i < lim) {
        acc += i * 3 + 1;
        i++;
    }
    return acc;
}

/* A `for` with the increment in the header — clang rotates this too, and the
 * increment must stay on the back-edge rather than migrating into the body. */
long for_accumulate(int n) {
    long acc = 0;
    for (int i = 0; i < (n & 15); i++) {
        acc = acc * 2 + i;
    }
    return acc;
}

/* A do-while: bottom-tested in BOTH compilers, so this is the control. If it
 * regresses while the others improve, the fix broke the shape that worked. */
long do_while_control(int n) {
    long acc = 0;
    int k = n & 15;
    do {
        acc += k;
        k--;
    } while (k > 0);
    return acc;
}

/* An early `return` out of a rotated loop: two exits, so the structurer cannot
 * assume the only way out is the loop test. */
/* HOIST TRAP — measured, do not "simplify" this loop's lowering.
 *
 * This function is one of exactly four the loop-header hoist fallback protects. The
 * verbose `while (1) { pre; if (!cond) break; }` form it decompiles to is NOT an
 * accident to be tidied away: hoisting the header above the loop lets constant
 * propagation substitute the initial value that dominates at the hoist position, which
 * freezes the loop-carried value and the loop stops making progress.
 *
 * Measured on branch `recover-ged-cells` (see docs/design/ged-recovery-measured-trade.md):
 * always-hoisting recovers 50.32 GED points, 46% of a regression — and breaks exactly
 * these four functions across six lanes:
 *     03_loop_shapes:gcc:O2:while_prefix
 *     12_loop_rotation:gcc:O2:find_first_set
 *     13_loop_early_exit:{clang,gcc}:O2:classify_run
 *     14_flag_effects:{clang,gcc}:O0:countdown
 * So the compact form is worth real score, and it is wrong. That is the trade.
 *
 * FOUR predicates have been tried and all four failed, each differently: a copy-chain
 * rule, a loop-invariance rule, a use-count rule, and a post-fold check requiring only a
 * nonempty read/write intersection (which passes `find_first_set`, whose body reassigns
 * its flag lower down while the frozen value sits inside the hoisted expression). If a
 * post-fold check is attempted again it must preserve EVERY original loop-carried
 * dependency, not one overlapping register.
 *
 * The real fix is typed value identity plus dominance, where "may this expression move
 * here" is a query rather than a guess — value-model-root-cause-and-plan.md Phase 2.
 */
int find_first_set(unsigned x) {
    for (int i = 0; i < 32; i++) {
        if ((x >> i) & 1u) {
            return i;
        }
    }
    return -1;
}

/* A `continue` inside a rotated loop: the back-edge is reached from two places,
 * which is where a goto-based lowering tends to duplicate or drop one. */
long skip_odd_sum(int n) {
    long acc = 0;
    int lim = n & 15;
    for (int i = 0; i < lim; i++) {
        if (i & 1) {
            continue;
        }
        acc += i;
    }
    return acc;
}

/* Nested rotated loops: the inner back-edge must not be confused with the
 * outer's. Returns a value sensitive to both trip counts. */
long nested_rotated(int a, int b) {
    long acc = 0;
    int la = a & 7, lb = b & 7;
    int i = 0;
    while (i < la) {
        int j = 0;
        while (j < lb) {
            acc = acc * 3 + (i ^ j);
            j++;
        }
        i++;
    }
    return acc;
}

/* A loop whose counter decrements by a NEGATIVE immediate — `add $-1` is what
 * clang emits, and reading that imm8 unsigned made the counter climb. Kept here
 * so the lifter fix has a differential test at the loop level too. */
long down_by_negative_imm(int n) {
    long acc = 0;
    int k = n & 15;
    while (k != 0) {
        acc = acc * 2 + k;
        k += -1;
    }
    return acc;
}
