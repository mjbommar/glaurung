/* Loops whose body can leave the function.
 *
 * At -O0 every `return` in a function jumps to ONE shared epilogue block, so a
 * `return` inside a loop makes that epilogue post-dominate the loop body. A
 * structurer that trusts the immediate post-dominator as an if/else join then
 * places the epilogue INSIDE the loop: the loop can run at most one iteration,
 * and the code after the loop loses its return.
 *
 * `sort:bsearch_i` in the DecBench corpus decompiled to exactly that — an
 * unconditional `return ret;` at the bottom of the loop and a trailing
 * `ret = -1;` with no `return` — and the graph-edit-distance metric scored it
 * fine. Only running it caught the problem, which is why these live here: the
 * fixture gate is execution-differential per function per lane.
 *
 * Each function below reaches the shared epilogue from a different place, so a
 * fix that special-cases one shape does not pass the rest.
 *
 * As committed, 19 of these 24 cells (6 functions x 4 lanes) FAIL. That is recorded
 * in baseline.json deliberately: the gate fails on new breakage while known bugs
 * stay visible. Two of the failures are not early-exit defects at all — see
 * `sum_positive` — so do not read a green fixture 13 as proof that Phase B worked
 * without checking WHICH cells moved.
 */

/* The canonical case: an early return from inside a loop, plus a fallthrough
 * return after it. Two paths into one epilogue. */
int find_first(const int *a, int n, int key) {
    for (int i = 0; i < n; i++) {
        if (a[i] == key) return i;
    }
    return -1;
}

/* The bsearch shape specifically: the early return is nested two conditionals
 * deep, and the sibling arms both continue the loop via a back edge. Those back
 * edges are what make the post-dominator the wrong join. */
int bisect(const int *a, int n, int key) {
    int lo = 0, hi = n - 1;
    while (lo <= hi) {
        int m = (lo + hi) / 2;
        if (a[m] == key) return m;
        if (a[m] < key) lo = m + 1;
        else hi = m - 1;
    }
    return -1;
}

/* Two early returns from the same loop, with different values, so a structurer
 * that collapses the epilogue into a single tail must still distinguish them. */
int classify_run(const int *a, int n) {
    for (int i = 1; i < n; i++) {
        if (a[i] < a[i - 1]) return -1;
        if (a[i] == a[i - 1]) return 0;
    }
    return 1;
}

/* An early return from a NESTED loop: the epilogue post-dominates both loop
 * bodies, so the wrong-join failure can occur at either depth. */
int has_pair(const int *a, int n, int target) {
    for (int i = 0; i < n; i++) {
        for (int j = i + 1; j < n; j++) {
            if (a[i] + a[j] == target) return 1;
        }
    }
    return 0;
}

/* A loop whose early exit is a `break` rather than a `return`: the join really
 * is inside the function, so this one should be structured as a loop with a break.
 * It was written as the counterexample that stops a fix from being "never use the
 * post-dominator" — but it does NOT currently pass. It decompiles with an
 * unconditional `return` at the bottom of the loop body and a `goto` to an empty
 * label, i.e. the same shape as `bisect`. So it is not yet a control; it is
 * another instance. Re-read this comment once Phase B lands. */
int sum_until_zero(const int *a, int n) {
    int s = 0;
    for (int i = 0; i < n; i++) {
        if (a[i] == 0) break;
        s += a[i];
    }
    return s;
}

/* A `continue` in the middle: a back edge from inside a conditional, which is
 * the same edge kind that misleads the join choice in `bisect` — but here there is
 * no early return, so structuring is NOT the problem.
 *
 * This one fails for two entirely different reasons, which is why it earns its
 * place: gcc -O0 emits the guard as `test %eax,%eax ; jle`, our `test` lifting
 * does not define Flag::Sle, so `jle` reads the stale Sle left by the loop's own
 * `cmp`; and the inverted condition then renders as `~sle`, where bitwise NOT of a
 * 0/1 flag is always true. The guard therefore never skips and the function sums
 * every element. Neither defect has anything to do with early exits — the fixture
 * found them by accident, which is the argument for fixtures over targeted cases. */
int sum_positive(const int *a, int n) {
    int s = 0;
    for (int i = 0; i < n; i++) {
        if (a[i] <= 0) continue;
        s += a[i];
    }
    return s;
}
