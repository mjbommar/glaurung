#include <stdint.h>

__attribute__((noinline)) int32_t graph_dfs(const int32_t *adjacency, int32_t n,
                                             int32_t start, int32_t *order) {
    int32_t stack[16];
    uint8_t seen[16] = {0};
    int32_t top = 0;
    int32_t count = 0;
    if (adjacency == 0 || order == 0 || n <= 0 || n > 4 || start < 0 ||
        start >= n) {
        return 0;
    }
    stack[top++] = start;
    while (top > 0) {
        int32_t vertex = stack[--top];
        int32_t next;
        if (seen[vertex] != 0) {
            continue;
        }
        seen[vertex] = 1;
        order[count++] = vertex;
        for (next = n - 1; next >= 0; --next) {
            if (adjacency[vertex * n + next] != 0 && seen[next] == 0) {
                stack[top++] = next;
            }
        }
    }
    return count;
}
