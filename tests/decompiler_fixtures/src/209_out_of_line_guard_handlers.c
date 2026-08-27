#include <stdint.h>

/* A chain of `if (c) { handler; }` guards whose handlers the compiler moves OUT
 * OF LINE, so each one sits after the function's tail and jumps back.
 *
 * THE LARGEST MEASURED DEFECT CLASS. Over the 250 scored DecBench sample-set
 * functions, 28.8% render as goto soup (40.5% on x86-64). A census of those
 * splits them by how much of the function was lost: only 2.6% are whole-
 * function bailouts, so `build_full`'s three refusals are NOT the cause. The
 * loss is `detect_if_shape` declining shape by shape and taking the remainder
 * of the walk with it — one conditional fails to match, and every block after
 * it lands in `Region::Unstructured`, which the renderer emits as one label per
 * block.
 *
 * `bin_090.elf sub_7370` in the frozen sample-set is the smallest instance: 15
 * blocks, 12 of them labelled. This fixture is that shape in C.
 *
 * WHY EXECUTION CANNOT SEE IT. Goto soup is FAITHFUL. Every arm is present,
 * every edge is real, the C compiles and returns the right answer for every
 * input. It is simply not the source's control flow. That is why this fixture
 * carries `goto_free` and `switch` structural assertions rather than relying on
 * the execution differential — before those predicates existed the corpus had
 * no way to state the property at all.
 *
 * NOT `105_goto_ladder` (which is ABOUT goto, in the source), and not
 * `107_short_circuit` (which is about operand evaluation order). The source
 * here contains no goto whatsoever.
 *
 * `__builtin_expect` marks the handlers cold so gcc and clang both sink them
 * below the return. The `cold` attribute would be stronger but is not available
 * on every toolchain in the matrix.
 */

/* The out-of-line note sink, kept in this translation unit so nothing links
 * against libc. `static` on purpose: it is covered inside its callers. */
static int32_t sink_value;

static int32_t record(int32_t value) {
    sink_value = value;
    return value;
}

/* Six guards, each with an out-of-line handler that rejoins the chain. The
 * source has no goto and no switch, so a faithful recovery is a nest of ifs. */
__attribute__((noinline)) int32_t guard_chain_rejoins(int32_t a, int32_t b,
                                                      int32_t c, int32_t d) {
    int32_t acc = 0;
    if (__builtin_expect(a > 100, 0)) {
        acc += record(a) & 0xf;
    }
    if (__builtin_expect(b > 100, 0)) {
        acc += record(b) & 0xf;
    }
    if (__builtin_expect(c > 100, 0)) {
        acc += record(c) & 0xf;
    }
    if (__builtin_expect(d > 100, 0)) {
        acc += record(d) & 0xf;
    }
    if (__builtin_expect(a > b, 0)) {
        acc += record(a - b) & 0xf;
    }
    if (__builtin_expect(c > d, 0)) {
        acc += record(c - d) & 0xf;
    }
    return acc + 1;
}

/* The same chain, but two of the guards EXIT through a shared epilogue instead
 * of rejoining. That mixture is what defeats the shape matcher: an exclusively
 * owned multi-block return chain has no owner among the shapes, because a
 * single terminal block is the early-exit case and a shared chain is the clone
 * case. */
__attribute__((noinline)) int32_t guard_chain_mixed_exits(int32_t a, int32_t b,
                                                          int32_t c,
                                                          int32_t *out) {
    int32_t acc = 0;
    if (out == 0) {
        return -1;
    }
    if (__builtin_expect(a > 100, 0)) {
        acc += record(a) & 0xf;
    }
    if (__builtin_expect(b < 0, 0)) {
        *out = acc;
        return -2;                       /* exits through the epilogue */
    }
    if (__builtin_expect(c > 100, 0)) {
        acc += record(c) & 0xf;
    }
    if (__builtin_expect(a > b, 0)) {
        *out = acc * 2;
        return -3;                       /* a second, distinct exit */
    }
    *out = acc;
    return acc + 1;
}

/* A guard whose handler is EXCLUSIVELY its own and reaches the return through
 * one further block. This is the exact shape that falls between every existing
 * pattern. */
__attribute__((noinline)) int32_t exclusive_handler_chain(int32_t a,
                                                          int32_t b) {
    int32_t acc = a ^ b;
    if (__builtin_expect(a < 0, 0)) {
        acc = record(acc);
        acc &= 0xff;
        return acc;                      /* two blocks, owned by this guard */
    }
    if (__builtin_expect(b < 0, 0)) {
        acc = record(-acc);
        acc |= 0x100;
        return acc;
    }
    return acc + 1;
}
