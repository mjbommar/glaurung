#include <stdint.h>

/* Branchless conditional code: A32 predication, Thumb-2 IT blocks, AArch64
 * `csel`, and x86 `cmov` — the same source shape lowered four different ways,
 * every one of which writes a register CONDITIONALLY.
 *
 * WHY THIS IS A DATAFLOW FIXTURE, NOT A CONTROL-FLOW ONE. A predicated write is
 * a conditional definition: after `mvnhi r0, #0`, `r0` holds either the new
 * value or its previous one, and which is a runtime fact. Our ARM handling
 * treats a definition as unconditional — `arm_defined_register` names the
 * register an instruction writes purely from the mnemonic, with no notion of a
 * predicate, and `DispatchTracker::kill_register` then discards everything
 * known about it. For a range bound that is the safe direction (a lost bound
 * costs a resolution). For a VALUE it is not: the two sides of the predicate
 * must both reach the reader, and a model with only one has to pick.
 *
 * This bit during the ARM jump-table work: a hand-written A32 reproduction of a
 * table dispatch compiled to `cmp r0,#7 / mvnhi r0,#0 / bxhi lr` — the guard's
 * failing path was PREDICATED rather than branched, so there was no conditional
 * branch for the bound to propagate across, and the dispatch declined. The
 * corpus firmware uses a real `bhi`, so the reproduction was unrepresentative
 * in a way that cost an afternoon. Nothing in the corpus covered predication,
 * which is why nothing said so.
 *
 * `14_flag_effects` covers flag producers and consumers on x86, where the
 * consumer is a branch or a `setcc`. `01_conditional_polarity` covers which arm
 * a branch takes. Neither has a conditionally-executed instruction.
 *
 * Written as ordinary C so every compiler picks its own branchless idiom; the
 * shapes below are the ones that reliably produce one at -O2. All lanes must
 * agree on the answer, which is what makes a mis-modelled conditional
 * definition visible.
 */

/* The canonical `cmov`/`csel`/`movhi` shape. */
__attribute__((noinline)) int32_t select_max(int32_t a, int32_t b) {
    return a > b ? a : b;
}

/* Two predicated writes to the SAME register in sequence, so a model that
 * keeps only the last definition produces a plausible wrong answer. */
__attribute__((noinline)) int32_t chained_selects(int32_t a, int32_t b,
                                                  int32_t c) {
    int32_t r = a;
    r = (b > r) ? b : r;
    r = (c > r) ? c : r;
    return r;
}

/* A predicated write whose value is CARRIED FORWARD when the predicate is
 * false: the false path is not a no-op, it is "keep what was there". This is
 * the case an unconditional-definition model gets wrong. */
__attribute__((noinline)) int32_t conditional_accumulate(const int32_t *values,
                                                          int32_t count) {
    int32_t acc = 0;
    int32_t last_positive = -1;
    if (values == 0 || count < 0 || count > 16) {
        return -1;
    }
    for (int32_t i = 0; i < count; i++) {
        int32_t v = values[i];
        acc += v;
        /* `last_positive` is written only on the taken side; on the other side
         * its previous value must survive. */
        last_positive = (v > 0) ? v : last_positive;
    }
    return acc + last_positive;
}

/* A predicated RETURN — on A32 this is `bxCC lr`, which ends the block without
 * a branch instruction and keeps lexical fallthrough. */
__attribute__((noinline)) int32_t early_out_branchless(int32_t a, int32_t b) {
    if (a < 0) {
        return -1;
    }
    return (a > b) ? (a - b) : (b - a);
}

/* Three-way branchless classification: enough predicated writes that a
 * conflated definition is arithmetically visible rather than coincidentally
 * equal. */
__attribute__((noinline)) int32_t branchless_classify(int32_t x, int32_t lo,
                                                      int32_t hi) {
    int32_t code = 0;
    code = (x < lo) ? 1 : code;
    code = (x > hi) ? 2 : code;
    code = (x == lo) ? 3 : code;
    code = (x == hi) ? 4 : code;
    return code * 10 + ((x < 0) ? 5 : 6);
}

/* CONTROL: the same decision written so every compiler emits real branches
 * (the arms have side effects and differing costs). If this fails too, the
 * defect is in branch handling and not in predication. */
static int32_t sink_value;

__attribute__((noinline)) int32_t branched_control(int32_t a, int32_t b) {
    if (a > b) {
        sink_value = a;
        return a * 3 + 1;
    }
    sink_value = b;
    return b * 5 + 2;
}
