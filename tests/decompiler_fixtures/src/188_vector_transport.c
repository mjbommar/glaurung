#include <stdint.h>

/* 128-bit memory transports, in the shapes that actually reach
 * `src/ir/vector_copy.rs`.
 *
 * A compiler lowers a plain element copy into packed XMM load/store batches,
 * and the lifter represents each batch as four independent dword lanes so
 * lane-wise arithmetic stays analyzable. Rejoining an untouched load/store pair
 * back into one 16-byte transport is what lets the C backend emit a copy
 * instead of four scalar moves.
 *
 * Before this fixture the entire pass had one lane — `09_memory_effects` at
 * `clang:O2` — and nothing covering the shape that matters most: two transports
 * INTERLEAVED, where each load batch is followed by its own scalar-view bridge
 * before either store batch appears. A fix that handled only a single
 * non-interleaved bridge passed its unit tests and still failed on a real
 * binary, because clang emits `load A / bridge A / load B / bridge B /
 * store A / store B`.
 *
 * `vt188_lane_math` is the control. Its loop reads and WRITES individual
 * elements with different values, so the batches are not an untouched
 * transport and must not be rejoined into a 16-byte copy. Recovering a
 * transport is only correct if it is not recovered where none exists. */

#define VT188_CAP 64

__attribute__((noinline)) int32_t vt188_copy_forward(int32_t *dst,
                                                    const int32_t *src,
                                                    int32_t count) {
    int32_t index;
    if (dst == 0 || src == 0 || count < 0 || count > VT188_CAP) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        dst[index] = src[index];
    }
    return count;
}

__attribute__((noinline)) int32_t vt188_copy_two_streams(int32_t *first_dst,
                                                        int32_t *second_dst,
                                                        const int32_t *src,
                                                        int32_t count) {
    int32_t index;
    if (first_dst == 0 || second_dst == 0 || src == 0 || count < 0 ||
        count > VT188_CAP) {
        return -1;
    }
    /* Two independent transports in one loop body. Vectorized, this is the
     * interleaved batch layout: both loads (each with its own scalar-view
     * bridge) precede both stores. */
    for (index = 0; index < count; ++index) {
        first_dst[index] = src[index];
        second_dst[index] = src[index];
    }
    return count;
}

__attribute__((noinline)) int32_t vt188_copy_backward(int32_t *dst,
                                                      const int32_t *src,
                                                      int32_t count) {
    int32_t index;
    if (dst == 0 || src == 0 || count < 0 || count > VT188_CAP) {
        return -1;
    }
    /* Descending order: the same transport with the address arithmetic running
     * the other way, so an address-adjacency check keyed on ascending
     * displacement alone does not accidentally pass. */
    for (index = count - 1; index >= 0; --index) {
        dst[index] = src[index];
    }
    return count;
}

__attribute__((noinline)) int32_t vt188_lane_math(int32_t *dst,
                                                  const int32_t *src,
                                                  int32_t count) {
    int32_t index;
    int32_t total = 0;
    if (dst == 0 || src == 0 || count < 0 || count > VT188_CAP) {
        return -1;
    }
    /* CONTROL: every element is transformed, so this is lane computation and
     * not a transport. Rejoining it into a 16-byte copy would silently drop
     * the arithmetic. */
    for (index = 0; index < count; ++index) {
        dst[index] = src[index] * 3 + 1;
        total += dst[index];
    }
    return total;
}
