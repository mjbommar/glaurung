#include <stdint.h>

/* A linked list whose head arrives as a PARAMETER and whose successor is a real
 * pointer load, over caller-owned memory the harness relocates.
 *
 * COVERAGE TARGET: `ir::loop_form::recover_sentinel_search_loops`, and more
 * generally every pass that has to keep a dependent-load walk distinct from an
 * affine walk. `dormant-transforms-2026-08-12.md` measured the sentinel pass at
 * 0 fires over the whole corpus and then isolated its single trigger: "the list
 * head arrives as a PARAMETER, and the advance is a pointer chase through a
 * struct field, under clang -O1 or above". Three near-misses were recorded as
 * NOT triggering it, and the corpus only contains those:
 *
 *   * pointer INCREMENT (`cursor += 1`)  -- the advance is arithmetic, not a load;
 *   * an INDEX walk over a caller-owned array, which is what
 *     `183_sentinel_list_search` does -- the exit test becomes a bound;
 *   * a linked walk over a `static` pool built in the same function -- the head
 *     is then a known constant and the builder loop perturbs the shape.
 *
 * `111_self_referential_struct` is the third of those: its nodes are a LOCAL
 * array it links itself, so nothing about it is caller-supplied.
 *
 * WHY THIS NEEDED A HARNESS FEATURE. Nodes linked by real addresses have to be
 * relocated to wherever the differential put the memory, and relocated
 * IDENTICALLY for the original and the rebuilt object or the two sides are not
 * running the same program. `tools/diff_decompile.py` materialises the nodes
 * from a declared element-index chain and resolves the links after allocation,
 * once per side, and reads any surviving link back as an element index.
 *
 * THE CHAIN IS NOT THE ARRAY ORDER. Every generated buffer is linked by the
 * manifest's `link_chains`: a scrambled, proper subset of the node array. That
 * is the whole point. With the identity successor (`nodes[i].next =
 * &nodes[i+1]`) a recovery that turns `p = p->next` into `p += 1` computes the
 * SAME answer on every input, and a fixture built that way proves nothing about
 * pointer chasing. Under a scrambled chain the two disagree on the first vector.
 *
 * `l192_scan_index_control` is the DEGENERACY CONTROL: the same search over the
 * same node type walked BY INDEX, which the ordinary affine recovery already
 * handles and which must keep passing. It is also the near-miss: it is the
 * function a chase-to-stride confusion gets RIGHT, so a decompiler cannot
 * satisfy this fixture by refusing to transform anything, and cannot satisfy it
 * by treating every struct walk as a chase either.
 *
 * Observables are caller-owned so the differential sees them directly:
 * `l192_find_key` returns a node compared by its index within the caller's
 * buffer, `l192_chase_keys` writes the visit ORDER into a caller-owned int
 * buffer, and `l192_stamp_chain` mutates the nodes it visits, so a walk that
 * visits the wrong set of nodes is caught even when the return value agrees. */

#define L192_MAX 16

struct L192Node {
    struct L192Node *next;
    int32_t key;
    int32_t payload;
};

/* THE TRIGGER SHAPE, character for character the probe from
 * `dormant-transforms-2026-08-12.md`: parameter head, `p = p->next`, NULL
 * sentinel, no counter. Do not add a step bound here -- a second exit test is
 * one of the things measured NOT to trigger the recovery. Termination is a
 * property of the input instead: `link_chains` is validated acyclic (each
 * element index appears at most once), and the differential caps the rebuilt
 * side at DECOMPILED_CALL_BUDGET_S, so a recovery that walks off the chain is
 * reported as a divergence rather than hanging the gate. */
__attribute__((noinline)) struct L192Node *l192_find_key(struct L192Node *head,
                                                         int32_t key) {
    struct L192Node *p = head;
    while (p != 0) {
        if (p->key == key) {
            return p;
        }
        p = p->next;
    }
    return 0;
}

/* The visit ORDER, recorded into the caller's own buffer. This is the function
 * that makes a chase-to-stride confusion observable on EVERY vector rather than
 * only on the ones where a search happens to hit: under a scrambled chain the
 * recorded keys are a permuted proper subset of the array's keys. */
__attribute__((noinline)) int32_t l192_chase_keys(struct L192Node *head, int32_t *out,
                                                  int32_t limit) {
    struct L192Node *cursor = head;
    int32_t count = 0;
    if (out == 0 || limit <= 0 || limit > L192_MAX) {
        return -1;
    }
    while (cursor != 0 && count < limit) {
        out[count] = cursor->key;
        count += 1;
        cursor = cursor->next;
    }
    return count;
}

/* An order-DEPENDENT accumulation: the prefix of the chain before the first
 * match. A total over the whole chain would be order-independent and would
 * survive a walk that visited the same nodes in the wrong sequence. */
__attribute__((noinline)) int32_t l192_sum_until_key(struct L192Node *head,
                                                     int32_t key) {
    struct L192Node *cursor = head;
    int32_t total = 0;
    int32_t steps = 0;
    while (cursor != 0) {
        if (cursor->key == key) {
            break;
        }
        total = (int32_t)((uint32_t)total + (uint32_t)cursor->payload);
        steps += 1;
        cursor = cursor->next;
    }
    return (int32_t)((uint32_t)total * 32u + (uint32_t)steps);
}

/* Mutation through the chase. The differential snapshots the whole node buffer,
 * so this pins the SET of nodes visited: the off-chain nodes must come back
 * untouched, which a stride walk cannot arrange. */
__attribute__((noinline)) int32_t l192_stamp_chain(struct L192Node *head,
                                                   int32_t stamp) {
    struct L192Node *cursor = head;
    int32_t visited = 0;
    while (cursor != 0) {
        cursor->payload = (int32_t)((uint32_t)cursor->payload + (uint32_t)stamp);
        visited += 1;
        cursor = cursor->next;
    }
    return visited;
}

/* DEGENERACY / NEAR-MISS CONTROL: the same search over the same nodes, walked
 * by INDEX. The successor here really is `+ 1`, so this is the answer a
 * chase-to-stride confusion produces -- and it must keep passing, because it is
 * the shape the ordinary affine recovery already handles. A decompiler that
 * satisfies this fixture by never transforming a struct walk fails here. */
__attribute__((noinline)) int32_t l192_scan_index_control(const struct L192Node *nodes,
                                                          int32_t count, int32_t key) {
    int32_t index;
    if (nodes == 0 || count < 0 || count > L192_MAX) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        if (nodes[index].key == key) {
            return index;
        }
    }
    return -1;
}
