#include <stdint.h>

__attribute__((noinline)) int32_t graph_bfs(const int32_t *adjacency, int32_t n,
                                             int32_t start, int32_t *order) {
    int32_t queue[16];
    uint8_t seen[16] = {0};
    int32_t head = 0;
    int32_t tail = 0;
    int32_t count = 0;
    if (adjacency == 0 || order == 0 || n <= 0 || n > 4 || start < 0 ||
        start >= n) {
        return 0;
    }
    queue[tail++] = start;
    seen[start] = 1;
    while (head < tail) {
        int32_t vertex = queue[head++];
        int32_t next;
        order[count++] = vertex;
        for (next = 0; next < n; ++next) {
            if (adjacency[vertex * n + next] != 0 && seen[next] == 0) {
                seen[next] = 1;
                queue[tail++] = next;
            }
        }
    }
    return count;
}
