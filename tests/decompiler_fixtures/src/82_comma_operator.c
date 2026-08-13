#include <stdint.h>

/* The comma operator: each left operand is evaluated and discarded, with a
 * sequence point between. Recovering this correctly means keeping the discarded
 * side effects AND their order, which a value-only view of the code loses. */

__attribute__((noinline)) int32_t
comma_chain(int32_t seed, int32_t *trace) {
    int32_t a = 0;
    int32_t b = 0;
    int32_t c = 0;
    if (trace == 0) {
        return -1;
    }
    /* Every assignment happens; only the last value is the result. */
    c = (a = seed + 1, b = a * 2, a + b);
    trace[0] = a;
    trace[1] = b;
    return c;
}

__attribute__((noinline)) int32_t
comma_in_for(int32_t count, int32_t *trace) {
    int32_t head;
    int32_t tail;
    int32_t steps = 0;
    if (trace == 0 || count < 0 || count > 16) {
        return -1;
    }
    for (head = 0, tail = count - 1; head < tail; ++head, --tail) {
        steps += 1;
    }
    trace[0] = head;
    trace[1] = tail;
    return steps;
}

__attribute__((noinline)) int32_t
comma_in_condition(int32_t limit, int32_t *counter) {
    int32_t total = 0;
    int32_t probe = 0;
    if (counter == 0 || limit < 0 || limit > 32) {
        return -1;
    }
    while (probe += 1, probe <= limit) {
        total += probe;
    }
    *counter = probe;
    return total;
}
