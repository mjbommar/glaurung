#include <stdint.h>

/* Early returns converging on ONE epilogue, at chain lengths 1, 2 and 3 — the
 * exact dimension along which the shape matcher's return-chain rule is written,
 * and the one no fixture varied.
 *
 * WHY EACH LENGTH IS A DIFFERENT SHAPE. `detect_if_shape` matches an early
 * return in three mutually exclusive ways:
 *
 *   * a SINGLE terminal block            -> the early-exit shape (runs first);
 *   * a SHARED multi-block chain         -> the clone shape, which duplicates
 *                                           the chain into the if-then body;
 *   * an EXCLUSIVELY OWNED multi-block chain -> no shape at all.
 *
 * The third case falls through every pattern, the conditional is emitted as a
 * bare block with a goto, and the rest of the walk lands in `Unstructured`.
 * `shared_return_chain` opens with `if cfg.preds[entry].len() <= 1 { return
 * None }`, so the chain is only recognised when it is shared — and sharing was
 * never what made cloning safe. The caller's `chain[..len - 1]` consumption
 * rule is.
 *
 * That gap was found, fixed, measured and REVERTED on 2026-08-27: admitting the
 * owned case took a transcription of `bin_090 sub_7370` from nine unstructured
 * blocks to one, kept all 91 structure tests green, moved nothing on the corpus,
 * and cost 26 new undefined reads in already-tracked rustc lanes
 * (`gen_defuse_baseline.py` refused the regeneration). It was the third local
 * fix to that function to be reverted after measurement.
 *
 * This fixture exists so the next attempt has something to measure against
 * BEFORE it is written. Each function pins one chain length, so a change that
 * trades one length for another shows up as one cell moving each way rather
 * than as a wash.
 *
 * `13_loop_early_exit` covers early exits inside a LOOP; this covers them in
 * straight-line code, where the epilogue is the function's own, and varies the
 * length rather than the loop shape.
 */

static int32_t sink_value;

static int32_t record(int32_t value) {
    sink_value = value;
    return value;
}

/* Length 1: the terminating arm is a single block. The early-exit shape owns
 * this, and it must keep owning it. */
__attribute__((noinline)) int32_t epilogue_chain_one(int32_t a, int32_t b) {
    if (a < 0) {
        return -1;
    }
    if (b < 0) {
        return -2;
    }
    return a + b;
}

/* Length 2: two blocks between the guard and the return, exclusively owned by
 * that guard. Nothing matches this today. */
__attribute__((noinline)) int32_t epilogue_chain_two(int32_t a, int32_t b) {
    int32_t acc = a ^ b;
    if (a < 0) {
        acc = record(acc);
        return acc - 1;
    }
    if (b < 0) {
        acc = record(-acc);
        return acc - 2;
    }
    return acc + 3;
}

/* Length 3, and the tail is SHARED by both guards, so the clone rule applies
 * rather than the owned rule. Pinning both in one fixture is what makes a trade
 * between them visible. */
__attribute__((noinline)) int32_t epilogue_chain_three_shared(int32_t a,
                                                              int32_t b,
                                                              int32_t *out) {
    int32_t acc = a | b;
    if (out == 0) {
        return -1;
    }
    if (a < 0) {
        acc = record(acc);
        acc &= 0xffff;
        *out = acc;
        return acc + 10;
    }
    if (b < 0) {
        acc = record(-acc);
        acc &= 0xffff;
        *out = acc;
        return acc + 20;
    }
    *out = acc;
    return acc + 30;
}

/* A chain long enough to hit the matcher's eight-block ceiling from below. If a
 * future rule raises or lowers that bound, this is where it shows. */
__attribute__((noinline)) int32_t epilogue_chain_long(int32_t a, int32_t b) {
    int32_t acc = a + b;
    if (a < 0) {
        acc = record(acc);
        acc ^= 0x11;
        acc += 3;
        acc ^= 0x22;
        acc += 5;
        return acc;
    }
    return acc + 1;
}

/* CONTROL: the two arms genuinely diverge — neither can reach the other's
 * terminal. A rule that treats a reconverging pair as an early return would
 * break this while leaving every function above passing. */
__attribute__((noinline)) int32_t divergent_arms(int32_t a, int32_t b) {
    if (a > b) {
        return record(a) + 100;
    }
    return record(b) + 200;
}
