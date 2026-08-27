#include <stdint.h>

/* A loop containing a multi-way dispatch, ONE OF WHOSE ARMS RETURNS.
 *
 * WHY THE RETURNING ARM IS THE WHOLE POINT. `Cfg::ipostdom` is computed once
 * per function against the function exit, with no notion of a loop-relative
 * join. When an arm inside the loop returns, the shared function epilogue
 * becomes the immediate post-dominator of every conditional in the loop body —
 * even though, for every path that continues iterating, the real join is the
 * latch. `detect_if_shape`'s post-dominator fallback then builds both arms with
 * `stop_at = Some(epilogue)`, the arm that continues walks straight past the
 * latch, and the loop body ends at the first case with the remainder stranded.
 *
 * The corrective guard at the fallback cannot fire for this shape: it requires
 * `stop_at.is_some()` (absent at function top level, where `build_full` passes
 * `None`) and either that the boundary does not dominate the conditional
 * (false inside a loop) or that a multiway block sits between the arm and the
 * boundary (false for a comparison ladder).
 *
 * This is the `statemachine` shape. It EXISTS in `tests/decbench_corpus/`, but
 * that population is scored by metric ratchet only — no execution differential,
 * no structural predicates, no arch sweep — so the fixture matrix has never
 * seen it. `04_switch_shapes` has a returning arm but no loop;
 * `13_loop_early_exit` has a returning loop but no dispatch;
 * `05_cleanup_and_state_machine` has a protocol FSM whose arms all `break`.
 * The combination is what fails, and nothing covered it.
 *
 * `fsm_returns_from_arm` is a byte-for-byte port of the DecBench program.
 */

/* The DecBench `statemachine` program: a for-loop containing a switch, one of
 * whose arms returns. */
__attribute__((noinline)) int32_t fsm_returns_from_arm(const uint8_t *in,
                                                       int32_t n) {
    int32_t st = 0;
    if (in == 0 || n < 0 || n > 32) {
        return -1;
    }
    for (int32_t i = 0; i < n; i++) {
        uint8_t c = in[i];
        switch (st) {
        case 0: st = (c == 'a') ? 1 : 0; break;
        case 1: st = (c == 'b') ? 2 : (c == 'a' ? 1 : 0); break;
        case 2: st = (c == 'c') ? 3 : 0; break;
        case 3: return 1;
        }
    }
    return st == 3;
}

/* Two returning arms with DIFFERENT values, so a structurer that merges them
 * into one epilogue changes the answer rather than only the shape. */
__attribute__((noinline)) int32_t two_returning_arms(const uint8_t *ops,
                                                     int32_t count) {
    int32_t acc = 0;
    if (ops == 0 || count < 0 || count > 32) {
        return -1;
    }
    for (int32_t i = 0; i < count; i++) {
        switch (ops[i] & 3) {
        case 0: acc += 1; break;
        case 1: return acc + 100;
        case 2: acc += 4; break;
        default: return acc + 200;
        }
    }
    return acc;
}

/* A returning arm in a NESTED loop: the inner dispatch's arm returns from the
 * whole function, so the epilogue post-dominates conditionals at two loop
 * depths. */
__attribute__((noinline)) int32_t nested_loop_returning_arm(const uint8_t *ops,
                                                            int32_t outer,
                                                            int32_t inner) {
    int32_t acc = 0;
    if (ops == 0 || outer < 0 || outer > 8 || inner < 0 || inner > 8) {
        return -1;
    }
    for (int32_t o = 0; o < outer; o++) {
        for (int32_t i = 0; i < inner; i++) {
            switch (ops[i] & 3) {
            case 0: acc += o; break;
            case 1: acc ^= i; break;
            case 2: return acc + 50;
            default: acc -= 1; break;
            }
        }
        acc += 7;
    }
    return acc;
}

/* CONTROL: the same loop and the same dispatch, with every arm breaking rather
 * than returning. The epilogue no longer post-dominates the body, so this must
 * recover cleanly — it isolates the returning arm as the cause. */
__attribute__((noinline)) int32_t all_arms_break(const uint8_t *ops,
                                                  int32_t count) {
    int32_t acc = 0;
    if (ops == 0 || count < 0 || count > 32) {
        return -1;
    }
    for (int32_t i = 0; i < count; i++) {
        switch (ops[i] & 3) {
        case 0: acc += 1; break;
        case 1: acc += 2; break;
        case 2: acc += 4; break;
        default: acc = 0; break;
        }
    }
    return acc;
}
