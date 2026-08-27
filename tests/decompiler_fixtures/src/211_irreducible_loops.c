#include <stdint.h>

/* Loops with MORE THAN ONE entry point — the graphs no schema matcher can
 * express, and the ones a region-based structurer exists to handle.
 *
 * WHY THIS IS DIFFERENT FROM EVERY OTHER LOOP FIXTURE. `03_loop_shapes`,
 * `12_loop_rotation`, `13_loop_early_exit` and `125_loop_shapes` are all
 * REDUCIBLE: one header dominates the whole body, so `natural_loop_body` finds
 * it from a single back edge. An irreducible loop has two headers and no
 * dominating entry, so `detect_natural_loop` cannot fire at all and
 * `build_full` reaches its `Region::Unstructured` fallback — the lossless
 * whole-function bailout that labels every block.
 *
 * That fallback is correct: `Region::{While,DoWhile}` carry exactly one `exit`,
 * so a multi-entry loop is UNREPRESENTABLE in the region algebra, and inventing
 * a header would move blocks across an edge the machine does not have. The
 * three refusals at the top of `build_full` exist precisely to detect this
 * before a shape can guess. So the fixture's near-term expectation is a
 * faithful goto rendering, and its long-term purpose is to be the acceptance
 * test for the region analysis that replaces the matcher: when `Region` grows
 * owned multi-exits, these functions are how you find out whether it worked.
 *
 * `145_control_flow_flattening` is an OLLVM dispatch loop — flattened, but
 * still reducible, with one header and one dispatcher. `102_duffs_device`
 * interleaves a switch with a loop but enters at exactly one place. Neither is
 * irreducible.
 *
 * A `goto` into a loop body is the only portable way to write one in C, so
 * unlike `209`/`210` this fixture's source DOES contain goto, and `goto_free`
 * is deliberately NOT asserted. What is asserted is that the recovery is
 * non-empty and executes identically — a bailout must stay faithful.
 */

/* The canonical two-entry loop. Which header the loop is entered through
 * depends on a runtime value, so no static choice of header is correct. */
__attribute__((noinline)) int32_t two_entry_loop(int32_t seed, int32_t count) {
    int32_t acc = 0;
    int32_t i = 0;
    if (count < 0 || count > 32) {
        return -1;
    }
    if (seed & 1) {
        goto odd_entry;
    }

even_entry:
    if (i >= count) {
        return acc;
    }
    acc += i * 2;
    i++;

odd_entry:
    if (i >= count) {
        return acc + 1;
    }
    acc ^= (i + seed) & 0xff;
    i++;
    goto even_entry;
}

/* Two loops sharing a body region, entered from different predecessors — the
 * shape a compiler produces from tail-merged loop bodies. */
__attribute__((noinline)) int32_t shared_body_loops(int32_t mode,
                                                    int32_t count) {
    int32_t acc = 0;
    int32_t i = 0;
    if (count < 0 || count > 32) {
        return -1;
    }
    if (mode > 0) {
        acc = 100;
        goto body;
    }
    acc = 200;

top:
    if (i >= count) {
        return acc;
    }

body:
    acc += (i * 3) & 0x3f;
    i++;
    if (i < count) {
        goto top;
    }
    return acc;
}

/* An irreducible loop NESTED inside a reducible one: the outer loop must still
 * be recovered even though the inner region cannot be. A structurer that bails
 * on the whole function loses the outer loop too, which is the difference
 * between a local and a global refusal. */
__attribute__((noinline)) int32_t irreducible_inside_reducible(int32_t outer,
                                                               int32_t inner) {
    int32_t acc = 0;
    if (outer < 0 || outer > 8 || inner < 0 || inner > 8) {
        return -1;
    }
    for (int32_t o = 0; o < outer; o++) {
        int32_t i = 0;
        if (o & 1) {
            goto second;
        }
    first:
        if (i >= inner) {
            continue;
        }
        acc += i;
        i++;
    second:
        if (i >= inner) {
            continue;
        }
        acc ^= i + o;
        i++;
        goto first;
    }
    return acc;
}

/* CONTROL: the identical arithmetic written as an ordinary reducible loop. It
 * must recover as a real loop with no goto; if it does not, the defect is in
 * loop recovery generally and not in irreducibility. */
__attribute__((noinline)) int32_t reducible_control(int32_t seed,
                                                    int32_t count) {
    int32_t acc = 0;
    if (count < 0 || count > 32) {
        return -1;
    }
    for (int32_t i = 0; i < count; i++) {
        acc += i * 2;
        acc ^= (i + seed) & 0xff;
    }
    return acc;
}
