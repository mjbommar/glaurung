#include <stdint.h>

/* A call with a side effect, sitting inside a conditional select.
 *
 * `lazy_call_select` and `copy_prop::move_adjacent_effectful_scratch_values`
 * fold a diamond into a ternary. That is only sound if the folded call is
 * evaluated exactly as often as the machine evaluated it. A fold that hoists
 * the call above the condition, or that duplicates it into both arms, still
 * produces plausible C with the right RETURN VALUE — the arithmetic is
 * unchanged — and is caught only by counting the effect.
 *
 * This is the same soundness class as the vector-transport bug in `188`: one
 * value with more than one consumer, where the transform assumed exactly one.
 * There the second consumer read undefined lanes; here the effect count moves.
 *
 * The count is kept in the caller's own buffer rather than a global, so it
 * survives the harness rebuilding a single function against extern callees,
 * and so the differential observes it directly.
 *
 * `se189_select_pure` is the control: no call in either arm, so folding is
 * entirely correct and must still happen. A fixture that only forbids folding
 * would be satisfied by a decompiler that never folds anything. */

#define SE189_SLOT_SELECTED 1
#define SE189_SLOT_WITNESS 2

__attribute__((noinline)) int32_t se189_bump(int32_t *calls, int32_t value) {
    if (calls == 0) {
        return -1;
    }
    calls[0] += 1;
    return value * 2 + 1;
}

__attribute__((noinline)) int32_t se189_select_call(int32_t *scratch, int32_t flag,
                                                    int32_t a, int32_t b) {
    int32_t selected;
    if (scratch == 0) {
        return -1;
    }
    scratch[0] = 0;
    /* Exactly one of these calls happens. If a fold evaluates both, or hoists
     * one above the branch, scratch[0] becomes 2 and the differential fails
     * even though the returned value is identical. */
    selected = flag ? se189_bump(scratch, a) : se189_bump(scratch, b);
    scratch[SE189_SLOT_SELECTED] = selected;
    scratch[SE189_SLOT_WITNESS] = scratch[0];
    return selected;
}

__attribute__((noinline)) int32_t se189_select_one_arm(int32_t *scratch, int32_t flag,
                                                       int32_t a, int32_t b) {
    int32_t selected;
    if (scratch == 0) {
        return -1;
    }
    scratch[0] = 0;
    /* Asymmetric: only the taken arm may call. Speculating the call so both
     * arms share one evaluation changes the count on the `b` path. */
    selected = flag ? se189_bump(scratch, a) : b;
    scratch[SE189_SLOT_SELECTED] = selected;
    scratch[SE189_SLOT_WITNESS] = scratch[0];
    return selected;
}

__attribute__((noinline)) int32_t se189_nested_select(int32_t *scratch, int32_t first,
                                                      int32_t second, int32_t a,
                                                      int32_t b) {
    int32_t selected;
    if (scratch == 0) {
        return -1;
    }
    scratch[0] = 0;
    /* Nested diamonds: at most one call on any path through both conditions. */
    selected = first ? (second ? se189_bump(scratch, a) : a) : (second ? b : se189_bump(scratch, b));
    scratch[SE189_SLOT_SELECTED] = selected;
    scratch[SE189_SLOT_WITNESS] = scratch[0];
    return selected;
}

__attribute__((noinline)) int32_t se189_select_pure(int32_t *scratch, int32_t flag,
                                                    int32_t a, int32_t b) {
    int32_t selected;
    if (scratch == 0) {
        return -1;
    }
    scratch[0] = 0;
    /* CONTROL: no call in either arm, so this diamond SHOULD fold to a ternary.
     * Present so the fixture cannot be satisfied by refusing to fold at all. */
    selected = flag ? (a * 2 + 1) : (b * 2 + 1);
    scratch[SE189_SLOT_SELECTED] = selected;
    scratch[SE189_SLOT_WITNESS] = scratch[0];
    return selected;
}
