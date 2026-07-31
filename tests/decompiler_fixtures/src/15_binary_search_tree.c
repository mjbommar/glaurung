#include <stdint.h>

typedef struct {
    int32_t key;
    int32_t left;
    int32_t right;
} BstNode;

__attribute__((noinline)) int32_t
bst_search(const BstNode *nodes, int32_t n, int32_t root, int32_t key) {
    int32_t current = root;
    int32_t steps;

    if (nodes == 0 || n <= 0 || n > 16) {
        return -1;
    }
    for (steps = 0; steps < n; ++steps) {
        if (current < 0 || current >= n) {
            return -1;
        }
        if (nodes[current].key == key) {
            return current;
        }
        current = key < nodes[current].key ? nodes[current].left
                                           : nodes[current].right;
    }
    return -1;
}

__attribute__((noinline)) uint32_t
bst_inorder_checksum(const BstNode *nodes, int32_t n, int32_t root) {
    int32_t stack[16];
    int32_t current = root;
    int32_t top = 0;
    int32_t visited = 0;
    uint32_t checksum = 0;

    if (nodes == 0 || n <= 0 || n > 16) {
        return 0;
    }
    while (visited < n && (top > 0 || (current >= 0 && current < n))) {
        while (current >= 0 && current < n && top < n) {
            stack[top++] = current;
            current = nodes[current].left;
        }
        if (top == 0) {
            break;
        }
        current = stack[--top];
        checksum = checksum * 33u + (uint32_t)nodes[current].key;
        ++visited;
        current = nodes[current].right;
    }
    return checksum;
}
