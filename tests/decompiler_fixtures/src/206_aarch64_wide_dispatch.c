#include <stdint.h>

/* A switch wide enough that every target lowers it to a JUMP TABLE rather than
 * a comparison tree, so each architecture's table-dispatch recogniser is
 * exercised by the same source.
 *
 * WHY THIS IS NOT `04_switch_shapes` OR `154_wide_switch`. Those fixtures are
 * about which arms are recovered and whether the exact case constants survive.
 * This one is about whether the DISPATCH ITSELF is recognised, per
 * architecture, and the two failure modes are completely different: an
 * unrecognised table does not produce wrong arms, it produces no arms at all —
 * the indirect branch contributes zero CFG successors and the case bodies never
 * enter the graph. `structure_accounting` cannot see that (it accounts the
 * region against the CFG, not against the program), and an execution
 * differential cannot see it either, because a function whose arms are missing
 * usually still returns the right value for the default case.
 *
 * `analysis::dispatch::DispatchTracker` has recognisers for x86 (register and
 * scaled-index forms) and for Thumb-2 `tbb`/`tbh`. It has NONE for AArch64:
 * grep `adrp` under `src/analysis/` and the hits are in `aarch64_literals.rs`
 * and `xrefs.rs`, never in `dispatch.rs`. Every AArch64 `br` therefore reports
 * `Unresolved::UnknownBase`. The `aarch64` lane of this fixture is expected to
 * fail on that, and it is the whole reason the fixture exists.
 *
 * `dense_dispatch` is the measurement. `sparse_dispatch` is the control: its
 * labels are far enough apart that no compiler builds a table for it, so it
 * must pass on every architecture — if it fails, the defect is in ladder
 * recovery and not in table recovery, and the two must not be confused.
 */

__attribute__((noinline)) int32_t dense_dispatch(int32_t op, int32_t a,
                                                 int32_t b) {
    switch (op) {
    case 0:  return a + b;
    case 1:  return a - b;
    case 2:  return a * 3 + b;
    case 3:  return a ^ b;
    case 4:  return a | b;
    case 5:  return a & b;
    case 6:  return (a >> 1) + b;
    case 7:  return (a << 1) - b;
    case 8:  return a + 100;
    case 9:  return b + 200;
    case 10: return a - 300;
    case 11: return b - 400;
    case 12: return a * 5;
    case 13: return b * 7;
    case 14: return a + b + 11;
    case 15: return a - b - 13;
    default: return -1;
    }
}

/* The control: labels chosen so the range is far wider than the arm count, so
 * every compiler emits comparisons rather than a table. */
__attribute__((noinline)) int32_t sparse_dispatch(int32_t op, int32_t a,
                                                  int32_t b) {
    switch (op) {
    case 3:      return a + b;
    case 700:    return a - b;
    case 60000:  return a * 3;
    case 900000: return b * 3;
    default:     return -1;
    }
}

/* A dense switch inside a loop, where one arm leaves the loop early. This is
 * the shape whose ownership the region structurer gets wrong: the returning arm
 * makes the function epilogue the immediate post-dominator of every conditional
 * inside the loop, so a globally-computed join is outside the loop body. */
__attribute__((noinline)) int32_t dispatch_in_loop(const uint8_t *ops,
                                                   int32_t count) {
    int32_t acc = 0;
    if (ops == 0 || count < 0 || count > 64) {
        return -1;
    }
    for (int32_t i = 0; i < count; i++) {
        switch (ops[i] & 7) {
        case 0: acc += 1; break;
        case 1: acc += 2; break;
        case 2: acc += 4; break;
        case 3: return acc;          /* the returning arm */
        case 4: acc -= 1; break;
        case 5: acc -= 2; break;
        case 6: acc ^= 0x55; break;
        default: acc = 0; break;
        }
    }
    return acc;
}
