#include <limits.h>
#include <stdint.h>

__attribute__((noinline)) int32_t dijkstra_dense(const int32_t *weights,
                                                  int32_t n, int32_t source,
                                                  int32_t *distance) {
    uint8_t used[16] = {0};
    int32_t iteration;
    int32_t i;
    if (weights == 0 || distance == 0 || n <= 0 || n > 4 || source < 0 ||
        source >= n) {
        return 0;
    }
    for (i = 0; i < n; ++i) {
        distance[i] = INT_MAX;
    }
    distance[source] = 0;
    for (iteration = 0; iteration < n; ++iteration) {
        int32_t best = -1;
        for (i = 0; i < n; ++i) {
            if (used[i] == 0 &&
                (best < 0 || distance[i] < distance[best])) {
                best = i;
            }
        }
        if (best < 0 || distance[best] == INT_MAX) {
            break;
        }
        used[best] = 1;
        for (i = 0; i < n; ++i) {
            int32_t weight = weights[best * n + i];
            if (weight > 0 && used[i] == 0 &&
                weight <= INT_MAX - distance[best] &&
                distance[best] + weight < distance[i]) {
                distance[i] = distance[best] + weight;
            }
        }
    }
    return distance[n - 1];
}
