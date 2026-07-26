/* Instructions whose FLAG side effects a later branch reads.
 *
 * At -O0 this mostly hides: gcc emits an explicit `cmp` or `test` immediately
 * before every conditional branch, and `cmp` is the one instruction whose flag
 * effects we model completely. At -O2 arithmetic-then-branch is the dominant
 * idiom — `sub $1,%edi ; jne`, `dec %ecx ; jnz`, `and %eax,%eax ; jz` — and the
 * lifter defines NO flags for any arithmetic instruction at all. A branch then
 * reads either a flag nothing defined, or worse, one left over from a `cmp`
 * outside the loop, which never updates.
 *
 * `dec_loop` below decompiled into an infinite loop for three compounding
 * reasons, all visible in one function:
 *
 *     zf = (arg0 == 0);            // `test` defines Z...
 *     if (sle) { return ret; }     // ...but `jle` reads Sle, which NOTHING defines
 *     L_1180: ;
 *     var1 = (var1 - 2);           // `sub` sets ZF; we define nothing
 *     if ((~zf)) { goto L_1180; }  // stale zf from OUTSIDE the loop, and `~` of a
 *                                  // 0/1 flag is always true
 *
 * The differential reported it as "did not terminate within 5.0s on an input the
 * original returned on", which is the only reason it was noticed — no metric
 * distinguishes an infinite loop from a slow one.
 *
 * These are written to be simple at -O0 and to force the flag-setting idioms at
 * -O2, so the -O2 lanes are the ones that matter here.
 */

/* Decrement-and-branch: the canonical `sub` sets ZF, `jne` reads it. */
int dec_loop(int n) {
    int c = 0;
    for (int i = n; i > 0; i--) c += i;
    return c;
}

/* Post-decrement in the condition — `while (n--)` is a flag read of the
 * decrement itself, with no separate compare anywhere. */
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
int countdown(int n) {
    int s = 0;
    while (n--) s += n;
    return s;
}

/* `sub` then a sign test on its result. -O2 turns this into sub/neg/cmovs, so it
 * also covers the `neg`-defines-SF path that `cmovs` consumes. */
int sub_then_sign(int a, int b) {
    int d = a - b;
    if (d < 0) return -d;
    return d;
}

/* `and` sets ZF; the compare against zero is redundant and -O2 removes it. */
int and_is_zero(unsigned x, unsigned m) {
    if ((x & m) == 0) return 1;
    return 0;
}

/* `add` sets SF, and a signed-overflow-free sign test reads it. */
int add_then_negative(int a, int b) {
    if (a + b < 0) return -1;
    return 1;
}

/* Shifts set ZF and SF. A shift-and-test loop is a common bit-scan idiom. */
int shift_until_zero(unsigned x) {
    int n = 0;
    while (x) { x >>= 1; n++; }
    return n;
}

/* `inc`/`dec` are special: they set SF/ZF/OF but deliberately LEAVE CF ALONE.
 * That is the reason they exist as distinct opcodes, and a model that derives
 * flags uniformly from "it is an arithmetic result" will get this wrong. `jbe`
 * after `dec` reads Ule = CF|ZF, whose CF half belongs to whatever set it last. */
int dec_preserves_carry(unsigned a, unsigned b) {
    unsigned d = a - b;   /* sets CF */
    int i = 3;
    i--;                  /* must NOT disturb CF */
    if (a < b) return i;  /* reads the CF from the subtraction */
    return d + i;
}
