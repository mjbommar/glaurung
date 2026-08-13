#include <stdint.h>

/* An iterative segment tree over a flat array: build, point update, and range
 * sum.  Index arithmetic climbs by halving and descends by doubling, so the
 * recovered loop must keep the parent/child relation exact. */

#define SEG_LEAVES 8
#define SEG_NODES (2 * SEG_LEAVES)

__attribute__((noinline)) int32_t
segment_build(const int32_t *values, int32_t count, int32_t *tree) {
    int32_t index;
    if (values == 0 || tree == 0 || count < 0 || count > SEG_LEAVES) {
        return -1;
    }
    for (index = 0; index < SEG_NODES; ++index) {
        tree[index] = 0;
    }
    for (index = 0; index < count; ++index) {
        tree[SEG_LEAVES + index] = values[index];
    }
    for (index = SEG_LEAVES - 1; index >= 1; --index) {
        tree[index] = tree[2 * index] + tree[2 * index + 1];
    }
    return tree[1];
}

__attribute__((noinline)) int32_t
segment_update(int32_t *tree, int32_t position, int32_t value) {
    int32_t node;
    if (tree == 0 || position < 0 || position >= SEG_LEAVES) {
        return -1;
    }
    node = SEG_LEAVES + position;
    tree[node] = value;
    for (node /= 2; node >= 1; node /= 2) {
        tree[node] = tree[2 * node] + tree[2 * node + 1];
    }
    return tree[1];
}

__attribute__((noinline)) int32_t
segment_range_sum(const int32_t *tree, int32_t low, int32_t high) {
    int32_t total = 0;
    int32_t left;
    int32_t right;
    if (tree == 0 || low < 0 || high > SEG_LEAVES || low > high) {
        return -1;
    }
    left = low + SEG_LEAVES;
    right = high + SEG_LEAVES;
    while (left < right) {
        if ((left & 1) != 0) {
            total += tree[left];
            left += 1;
        }
        if ((right & 1) != 0) {
            right -= 1;
            total += tree[right];
        }
        left /= 2;
        right /= 2;
    }
    return total;
}
