/* 03_loop_shapes.c
 *
 * Loop-shape fixture. Every function is a pure integer function whose result
 * depends on the EXACT loop structure a correct decompilation must recover:
 * how many times the body runs, whether the test is pre- or post-tested, where
 * the latches are, and — critically — that per-iteration header computation
 * stays INSIDE the loop and runs every iteration. A hoisted loop-header
 * computation, a do/while turned into a while (or vice versa), a dropped
 * back-edge, or a mis-placed break/continue changes the accumulated result,
 * which an execution-differential test catches.
 *
 * Targets review #4 (loop structuring). Several functions take an `int*` buffer
 * (the differential gate supplies a fresh buffer of 8 random ints) so the loop
 * is genuinely data-driven and header hoisting is observable. Keep every
 * function pure (no globals, no libc) and deterministic. Buffers are read-only
 * unless a comment says the function mutates.
 */
#include <stdint.h>

#define N 8   /* the differential gate drives pointer params as 8 ints */

/* --- counting for --------------------------------------------------- */

/* Plain counted for over the buffer: sum of 8 elements. A hoisted or
 * off-by-one bound changes the sum. */
int for_sum(const int *p) {
    int s = 0;
    for (int i = 0; i < N; i++)
        s += p[i];
    return s;
}

/* Counted for with a stride of 2 and a running weight — exercises that the
 * induction variable update is recovered exactly. */
int for_stride2(const int *p) {
    int s = 0;
    for (int i = 0; i < N; i += 2)
        s += p[i] * (i + 1);
    return s;
}

/* Counted-down for: bound and direction must survive. */
int for_countdown(const int *p) {
    int s = 0;
    for (int i = N - 1; i >= 0; i--)
        s = s * 3 + p[i];
    return s;
}

/* --- while (pre-tested) --------------------------------------------- */

/* Pre-tested while: the body must NOT run when the test is already false.
 * Here the walk stops at the first non-negative element, folding a prefix. */
int while_prefix(const int *p) {
    int i = 0;
    int s = 0;
    while (i < N && p[i] < 0) {
        s += p[i];
        i++;
    }
    return s * 10 + i;   /* i encodes how many iterations actually ran */
}

/* While whose HEADER reloads a buffer element every iteration: the loop
 * condition reads p[i] each pass. If the header load is hoisted out, the loop
 * either never terminates (broken) or folds the wrong count. The returned
 * value encodes the stopping index, so hoisting is directly observable. */
int while_reload_header(const int *p) {
    int i = 0;
    /* advance while the current element is even; the p[i] read is IN the
     * header and must execute on every iteration. */
    while (i < N && (p[i] & 1) == 0) {
        i++;
    }
    return i * 1000 + (i < N ? p[i] : -1);
}

/* --- do / while (post-tested, CRITICAL) ----------------------------- */

/* do/while: the body runs at least once even though the test could be false on
 * entry. If lowered as a pre-tested while, the first element is skipped and the
 * result changes. The post-test is evaluated every iteration. */
int dowhile_atleastonce(const int *p) {
    int i = 0;
    int s = 0;
    do {
        s += p[i];
        i++;
    } while (i < N && p[i - 1] > 0);
    return s * 10 + i;   /* i >= 1 always; a pre-test lowering could give 0 */
}

/* do/while that runs exactly once for an entry that fails the test — this is
 * the case a while() would skip entirely. The header recomputes `t` each pass. */
int dowhile_recompute(int x) {
    int s = 0;
    int t = x;
    do {
        s += t & 0xFF;
        t = t >> 8;      /* per-iteration header input, recomputed in the body */
    } while (t != 0);
    return s;            /* == sum of the byte lanes of x, at least one lane */
}

/* --- nested loops --------------------------------------------------- */

/* Nested loops over the buffer: an O(N^2) fold. The inner bound depends on the
 * outer index, so the trip count and the join structure must be exact. */
int nested_pairs(const int *p) {
    int s = 0;
    for (int i = 0; i < N; i++)
        for (int j = i; j < N; j++)
            s += p[i] ^ p[j];
    return s;
}

/* Nested loop where the inner loop mutates a running accumulator carried across
 * outer iterations — tests that the outer back-edge does not reset inner state
 * incorrectly. */
int nested_carry(const int *p) {
    int acc = 1;
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < N; j++)
            acc += (acc + p[j]) & 7;
    }
    return acc;
}

/* --- two back-edges / two latches (continue in the middle) ---------- */

/* A single loop with two latches: the `continue` creates a second back-edge
 * distinct from the fall-off-the-bottom back-edge. A structurer that collapses
 * them or reorders the guard changes which elements are folded. */
int two_latches(const int *p) {
    int s = 0;
    for (int i = 0; i < N; i++) {
        if ((p[i] & 1) != 0) {
            s -= 1;
            continue;         /* latch #1: back-edge from the middle */
        }
        s += p[i];
    }                          /* latch #2: normal loop-bottom back-edge */
    return s;
}

/* --- break --------------------------------------------------------- */

/* break out on the first element exceeding a threshold; the return encodes both
 * the partial sum and the break index. A dropped break folds the whole buffer. */
int loop_break(const int *p) {
    int s = 0;
    int i = 0;
    for (; i < N; i++) {
        if (p[i] > 1000000)
            break;
        s += p[i];
    }
    return s * 10 + i;
}

/* --- continue ------------------------------------------------------- */

/* continue to skip negative elements: only non-negatives are summed. Miscompiled
 * continue polarity flips which elements contribute. */
int loop_continue(const int *p) {
    int s = 0;
    for (int i = 0; i < N; i++) {
        if (p[i] < 0)
            continue;
        s += p[i];
    }
    return s;
}

/* --- early return from inside a loop -------------------------------- */

/* Early return the moment a zero element is found, yielding its index; if none,
 * return a sentinel. The in-loop return must not be sunk below the loop. */
int loop_early_return(const int *p) {
    for (int i = 0; i < N; i++) {
        if (p[i] == 0)
            return i + 1;
    }
    return -1;
}

/* Early return carrying a computed accumulator: returns as soon as the running
 * sum goes negative. */
int loop_return_on_neg(const int *p) {
    int s = 0;
    for (int i = 0; i < N; i++) {
        s += p[i];
        if (s < 0)
            return i * 100 + (s & 0xFF);
    }
    return s;
}

/* --- side-effecting / reloading loop condition ---------------------- */

/* The loop CONDITION contains a side-effecting update: `x = step(x)` runs, then
 * the comparison. The header must execute the assignment every iteration. If the
 * update is hoisted, the walk length changes. Returns the step count reached. */
static int step_index(int x) {
    return (x * 5 + 1) & (N - 1);   /* stays within [0, N) */
}

int cond_side_effect(int x) {
    int count = 0;
    int guard = 0;
    /* comma operator in the header: update THEN test, every iteration. */
    while ((x = step_index(x), guard++ , guard < N)) {
        count += x;
    }
    return count * 10 + guard;
}

/* Loop whose header reads a NEW pointer element each pass to decide
 * continuation, while the body accumulates a transform. Both the header read
 * and the body run per iteration; hoisting the header read breaks termination
 * or the fold. */
int cond_reload_and_transform(const int *p) {
    int s = 0;
    int i = 0;
    while (i < N && (p[i] % 7) != 3) {   /* header reload of p[i] each pass */
        s += p[i] * 2 - 1;
        i++;
    }
    return s * 10 + i;
}

/* --- buffer-mutating loop (differential gate compares before/after) --- */

/* Mutates the passed-in buffer in place: each element becomes a running prefix
 * transform. The gate compares the buffer before/after, so a loop that runs the
 * wrong number of times or hoists the carry is caught by the mutation diff. */
void mutate_prefix(int *p) {
    int carry = 3;
    for (int i = 0; i < N; i++) {
        int v = p[i] + carry;
        carry = (carry * 2 + p[i]) & 0xFFFF;   /* carry recomputed each pass */
        p[i] = v;
    }
}

/* In-place reverse via a two-index loop with a single latch: exercises that the
 * bound (i < j) is recovered exactly. */
void mutate_reverse(int *p) {
    int i = 0, j = N - 1;
    while (i < j) {
        int t = p[i];
        p[i] = p[j];
        p[j] = t;
        i++;
        j--;
    }
}
