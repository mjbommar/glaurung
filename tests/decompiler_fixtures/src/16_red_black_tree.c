#include <stdint.h>

typedef struct {
    int32_t key;
    int32_t left;
    int32_t right;
    uint32_t color;
} RbNode;

__attribute__((noinline)) int32_t
rb_validate(const RbNode *nodes, int32_t n, int32_t root) {
    int32_t parents[16] = {0};
    int32_t node_stack[32];
    int32_t black_stack[32];
    int32_t expected_black = -1;
    int32_t top = 0;
    int32_t i;

    if (nodes == 0 || n <= 0 || n > 16 || root < 0 || root >= n) {
        return 0;
    }
    if (nodes[root].color != 0u) {
        return 0;
    }
    for (i = 0; i < n; ++i) {
        int32_t children[2] = {nodes[i].left, nodes[i].right};
        int32_t side;
        if (nodes[i].color > 1u) {
            return 0;
        }
        for (side = 0; side < 2; ++side) {
            int32_t child = children[side];
            if (child == -1) {
                continue;
            }
            if (child < 0 || child >= n || ++parents[child] != 1) {
                return 0;
            }
            if ((side == 0 && nodes[child].key >= nodes[i].key) ||
                (side == 1 && nodes[child].key <= nodes[i].key)) {
                return 0;
            }
            if (nodes[i].color == 1u && nodes[child].color == 1u) {
                return 0;
            }
        }
    }
    if (parents[root] != 0) {
        return 0;
    }
    for (i = 0; i < n; ++i) {
        if (i != root && parents[i] != 1) {
            return 0;
        }
    }

    node_stack[top] = root;
    black_stack[top++] = 0;
    while (top > 0) {
        int32_t node;
        int32_t black_count;
        int32_t children[2];
        int32_t side;
        --top;
        node = node_stack[top];
        black_count = black_stack[top] + (nodes[node].color == 0u ? 1 : 0);
        children[0] = nodes[node].left;
        children[1] = nodes[node].right;
        for (side = 0; side < 2; ++side) {
            if (children[side] == -1) {
                if (expected_black < 0) {
                    expected_black = black_count;
                } else if (black_count != expected_black) {
                    return 0;
                }
            } else {
                if (top >= 32) {
                    return 0;
                }
                node_stack[top] = children[side];
                black_stack[top++] = black_count;
            }
        }
    }
    return 1;
}
