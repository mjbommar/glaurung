#include <stdint.h>

/* A struct containing a pointer to its own type. The nodes live in a
 * caller-owned array and are linked by real addresses, so traversal is a chain
 * of dependent loads that must terminate on the recovered null test. */

struct Node {
    int32_t value;
    struct Node *next;
};

#define NODE_MAX 8

__attribute__((noinline)) int32_t
link_and_sum(int32_t *values, int32_t count) {
    struct Node nodes[NODE_MAX];
    struct Node *cursor;
    int32_t index;
    int32_t total = 0;
    int32_t visited = 0;
    if (values == 0 || count < 0 || count > NODE_MAX) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        nodes[index].value = values[index];
        nodes[index].next = (index + 1 < count) ? &nodes[index + 1] : 0;
    }
    for (cursor = (count > 0) ? &nodes[0] : 0; cursor != 0;
         cursor = cursor->next) {
        total += cursor->value;
        visited += 1;
        if (visited > NODE_MAX) {
            return -2;
        }
    }
    return total * 10 + visited;
}
