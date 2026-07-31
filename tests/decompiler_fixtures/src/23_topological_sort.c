#include <stdint.h>

__attribute__((noinline)) int32_t topological_sort(const int32_t *adjacency,
                                                    int32_t n,
                                                    int32_t *order) {
    int32_t indegree[16] = {0};
    int32_t queue[16];
    int32_t head = 0;
    int32_t tail = 0;
    int32_t count = 0;
    int32_t from;
    int32_t to;
    if (adjacency == 0 || order == 0 || n < 0 || n > 4) {
        return -1;
    }
    for (from = 0; from < n; ++from) {
        for (to = 0; to < n; ++to) {
            if (adjacency[from * n + to] != 0) {
                ++indegree[to];
            }
        }
    }
    for (to = 0; to < n; ++to) {
        if (indegree[to] == 0) {
            queue[tail++] = to;
        }
    }
    while (head < tail) {
        from = queue[head++];
        order[count++] = from;
        for (to = 0; to < n; ++to) {
            if (adjacency[from * n + to] != 0 && --indegree[to] == 0) {
                queue[tail++] = to;
            }
        }
    }
    return count == n ? count : -1;
}
