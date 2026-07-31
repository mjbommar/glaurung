#include <stdint.h>

static int32_t find_root(const int32_t *parent, int32_t n, int32_t x) {
    int32_t steps;
    if (x < 0 || x >= n) {
        return -1;
    }
    for (steps = 0; steps < n; ++steps) {
        int32_t next = parent[x];
        if (next == x) {
            return x;
        }
        if (next < 0 || next >= n) {
            return -1;
        }
        x = next;
    }
    return -1;
}

__attribute__((noinline)) int32_t dsu_find(int32_t *parent, int32_t n,
                                           int32_t x) {
    int32_t root;
    int32_t steps;
    if (parent == 0 || n <= 0 || n > 16) {
        return -1;
    }
    root = find_root(parent, n, x);
    if (root < 0) {
        return -1;
    }
    for (steps = 0; steps < n && x != root; ++steps) {
        int32_t next = parent[x];
        parent[x] = root;
        x = next;
    }
    return root;
}

__attribute__((noinline)) int32_t dsu_union(int32_t *parent, int32_t *rank,
                                            int32_t n, int32_t a, int32_t b) {
    int32_t ra;
    int32_t rb;
    if (parent == 0 || rank == 0 || n <= 0 || n > 16) {
        return -1;
    }
    ra = find_root(parent, n, a);
    rb = find_root(parent, n, b);
    if (ra < 0 || rb < 0) {
        return -1;
    }
    if (ra == rb) {
        return ra;
    }
    if (rank[ra] < rank[rb]) {
        parent[ra] = rb;
        return rb;
    }
    parent[rb] = ra;
    if (rank[ra] == rank[rb] && rank[ra] < INT32_MAX) {
        ++rank[ra];
    }
    return ra;
}
