/* Independent textbook-example checks for the curriculum source corpus.
 *
 * The round-trip differential proves that recovered code matches the original
 * binary.  This driver separately proves that the original programs implement
 * the algorithms claimed by the catalog, preventing two equally wrong programs
 * from looking like a successful differential.
 */
#include <limits.h>
#include <stdint.h>
#include <stdio.h>

#include "src/15_binary_search_tree.c"
#include "src/16_red_black_tree.c"
#include "src/17_hash_table.c"
#include "src/18_binary_heap.c"
#include "src/19_disjoint_set.c"
#include "src/20_graph_bfs.c"
#include "src/21_graph_dfs.c"
#include "src/22_dijkstra.c"
#include "src/23_topological_sort.c"
#include "src/24_merge_sort.c"
#include "src/25_kmp_search.c"
#include "src/26_sparse_matrix.c"
#include "src/27_newton_raphson.c"
#include "src/28_euler_ode.c"
#include "src/29_polynomial.c"
#include "src/30_finite_difference.c"

#define CHECK(condition, code)                                                \
    do {                                                                       \
        if (!(condition)) {                                                    \
            fprintf(stderr, "curriculum oracle failed at check %d\n", code); \
            return code;                                                       \
        }                                                                      \
    } while (0)

static int same_i32(const int32_t *left, const int32_t *right, int32_t n) {
    int32_t i;
    for (i = 0; i < n; ++i) {
        if (left[i] != right[i]) {
            return 0;
        }
    }
    return 1;
}

int main(void) {
    BstNode bst[] = {{8, 1, 2}, {4, 3, 4}, {12, 5, 6}, {2, -1, -1},
                     {6, -1, -1}, {10, -1, -1}, {14, -1, -1}};
    RbNode rb[] = {{8, 1, 2, 0}, {4, 3, 4, 1}, {12, 5, 6, 1},
                   {2, -1, -1, 0}, {6, -1, -1, 0}, {10, -1, -1, 0},
                   {14, -1, -1, 0}};
    int32_t keys[16];
    int32_t hash_values[16] = {0};
    int32_t heap[16] = {2, 5, 7, 12, 9, 11};
    int32_t removed[16] = {0};
    int32_t parent[16] = {0, 0, 2, 2, 4, 4};
    int32_t rank[16] = {1, 0, 1, 0, 1, 0};
    int32_t graph[] = {0, 1, 1, 0, 1, 0, 0, 1,
                       1, 0, 0, 1, 0, 1, 1, 0};
    int32_t dag[] = {0, 1, 1, 0, 0, 0, 0, 1,
                     0, 0, 0, 1, 0, 0, 0, 0};
    int32_t weights[] = {0, 4, 1, 0, 4, 0, 2, 5,
                         1, 2, 0, 8, 0, 5, 8, 0};
    int32_t output[16] = {0};
    int32_t expected[16] = {0};
    int32_t sortable[16] = {9, -3, 7, 7, 0, 12, -8, 1};
    uint8_t text[] = {1, 2, 1, 2, 1, 3};
    uint8_t pattern[] = {1, 2, 1, 3};
    int32_t row_offsets[] = {0, 2, 3, 5, 7};
    int32_t columns[] = {0, 3, 1, 0, 2, 1, 3};
    int32_t sparse_values[] = {10, 2, 3, 4, 5, 6, 7};
    int32_t vector[] = {1, 2, 3, 4};
    uint32_t sparse_output[16] = {0};
    uint32_t coefficients[] = {1, 2, 3, 4};
    int32_t heat_source[] = {0, 0, 100, 0, 0};
    int32_t heat_destination[16] = {0};
    int32_t i;

    CHECK(bst_search(bst, 7, 0, 10) == 5, 1);
    CHECK(bst_search(bst, 7, 0, 11) == -1, 2);
    CHECK(bst_inorder_checksum(bst, 7, 0) == 2746891832u, 3);

    CHECK(rb_validate(rb, 7, 0) == 1, 4);
    rb[0].color = 1;
    CHECK(rb_validate(rb, 7, 0) == 0, 5);

    for (i = 0; i < 16; ++i) {
        keys[i] = INT32_MIN;
    }
    CHECK(hash_insert(keys, hash_values, 8, 9, 90) == 1, 6);
    CHECK(hash_insert(keys, hash_values, 8, 17, 170) == 2, 7);
    CHECK(hash_lookup(keys, hash_values, 8, 17) == 170, 8);
    CHECK(hash_insert(keys, hash_values, 8, 25, 250) == 3, 9);

    CHECK(heap_push(heap, 6, 16, 3) == 7, 10);
    expected[0] = 2;
    expected[1] = 5;
    expected[2] = 3;
    expected[3] = 12;
    expected[4] = 9;
    expected[5] = 11;
    expected[6] = 7;
    CHECK(same_i32(heap, expected, 7), 11);
    CHECK(heap_pop(heap, 7, removed) == 6 && removed[0] == 2, 12);

    CHECK(dsu_find(parent, 6, 1) == 0, 13);
    CHECK(dsu_union(parent, rank, 6, 1, 5) == 0, 14);
    CHECK(parent[4] == 0 && rank[0] == 2, 15);

    expected[0] = 0;
    expected[1] = 1;
    expected[2] = 2;
    expected[3] = 3;
    CHECK(graph_bfs(graph, 4, 0, output) == 4 && same_i32(output, expected, 4),
          16);
    for (i = 0; i < 16; ++i) {
        output[i] = 0;
    }
    expected[0] = 0;
    expected[1] = 1;
    expected[2] = 3;
    expected[3] = 2;
    CHECK(graph_dfs(graph, 4, 0, output) == 4 && same_i32(output, expected, 4),
          17);

    CHECK(dijkstra_dense(weights, 4, 0, output) == 8, 18);
    expected[0] = 0;
    expected[1] = 3;
    expected[2] = 1;
    expected[3] = 8;
    CHECK(same_i32(output, expected, 4), 19);

    CHECK(topological_sort(dag, 4, output) == 4, 20);
    expected[0] = 0;
    expected[1] = 1;
    expected[2] = 2;
    expected[3] = 3;
    CHECK(same_i32(output, expected, 4), 21);

    CHECK(merge_sort_i32(sortable, 8) == 7, 22);
    expected[0] = -8;
    expected[1] = -3;
    expected[2] = 0;
    expected[3] = 1;
    expected[4] = 7;
    expected[5] = 7;
    expected[6] = 9;
    expected[7] = 12;
    CHECK(same_i32(sortable, expected, 8), 23);
    CHECK(kmp_search(text, 6, pattern, 4) == 2, 24);

    CHECK(csr_matvec(row_offsets, columns, sparse_values, vector, sparse_output,
                     4, 4, 7) == 542633u,
          25);
    CHECK(sparse_output[0] == 18u && sparse_output[1] == 6u &&
              sparse_output[2] == 19u && sparse_output[3] == 40u,
          26);
    CHECK(newton_isqrt(1000000u) == 1000u, 27);
    CHECK(newton_isqrt(UINT32_MAX) == 65535u, 28);
    CHECK(euler_decay_q16(65536, 16384, 2) == 36864, 29);
    CHECK(polynomial_eval_mod32(coefficients, 4, 5) == 586u, 30);
    CHECK(polynomial_derivative_mod32(coefficients, 4, 5) == 332u, 31);
    CHECK(heat_step_1d(heat_destination, heat_source, 5) == 953700u, 32);
    expected[0] = 0;
    expected[1] = 25;
    expected[2] = 50;
    expected[3] = 25;
    expected[4] = 0;
    CHECK(same_i32(heat_destination, expected, 5), 33);
    return 0;
}
