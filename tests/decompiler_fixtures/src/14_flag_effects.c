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
