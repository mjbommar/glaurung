#include <stdint.h>

/* Huffman code lengths by repeated two-smallest merging over a flat node
 * array, then the Kraft sum of the resulting lengths.  The two-minimum scan
 * carries two indices and two values through one loop body. */

#define HUFF_SYMBOLS 8
#define HUFF_NODES (2 * HUFF_SYMBOLS)

__attribute__((noinline)) int32_t
huffman_code_lengths(const int32_t *frequencies, int32_t symbols,
                     int32_t *lengths) {
    int32_t weight[HUFF_NODES];
    int32_t parent[HUFF_NODES];
    int32_t alive[HUFF_NODES];
    int32_t nodes;
    int32_t index;
    int32_t total = 0;
    if (frequencies == 0 || lengths == 0 || symbols < 1 ||
        symbols > HUFF_SYMBOLS) {
        return -1;
    }
    for (index = 0; index < HUFF_NODES; ++index) {
        weight[index] = 0;
        parent[index] = -1;
        alive[index] = 0;
    }
    for (index = 0; index < symbols; ++index) {
        if (frequencies[index] < 0 || frequencies[index] > 1000) {
            return -2;
        }
        weight[index] = frequencies[index];
        alive[index] = 1;
        lengths[index] = 0;
    }
    nodes = symbols;
    while (nodes < HUFF_NODES) {
        int32_t first = -1;
        int32_t second = -1;
        int32_t scan;
        for (scan = 0; scan < nodes; ++scan) {
            if (!alive[scan]) {
                continue;
            }
            if (first < 0 || weight[scan] < weight[first]) {
                second = first;
                first = scan;
            } else if (second < 0 || weight[scan] < weight[second]) {
                second = scan;
            }
        }
        if (first < 0 || second < 0) {
            break;
        }
        weight[nodes] = weight[first] + weight[second];
        alive[nodes] = 1;
        alive[first] = 0;
        alive[second] = 0;
        parent[first] = nodes;
        parent[second] = nodes;
        nodes += 1;
    }
    for (index = 0; index < symbols; ++index) {
        int32_t depth = 0;
        int32_t walk = index;
        while (parent[walk] >= 0 && depth < HUFF_NODES) {
            walk = parent[walk];
            depth += 1;
        }
        lengths[index] = depth;
        total += depth;
    }
    return total;
}

__attribute__((noinline)) uint32_t
kraft_sum_q16(const int32_t *lengths, int32_t symbols) {
    uint32_t total = 0;
    int32_t index;
    if (lengths == 0 || symbols < 0 || symbols > HUFF_SYMBOLS) {
        return 0;
    }
    for (index = 0; index < symbols; ++index) {
        int32_t length = lengths[index];
        if (length > 0 && length < 16) {
            total += (uint32_t)65536 >> (uint32_t)length;
        }
    }
    return total;
}
