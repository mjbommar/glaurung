#include <stdint.h>

/* Thread-local storage uses an addressing mode nothing else does: the object is
 * reached through a thread pointer (%fs on x86-64) plus a link-time TLS offset,
 * or through a __tls_get_addr call under the general-dynamic model. A recovery
 * that treats it as an ordinary global is wrong in a way no other fixture can
 * detect, because the address differs per thread. */

static __thread int32_t tls_counter = 100;
static __thread int32_t tls_table[4] = {1, 2, 3, 4};
static int32_t global_counter = 100;

__attribute__((noinline)) int32_t tls_increment(int32_t amount) {
    tls_counter += amount;
    return tls_counter;
}

__attribute__((noinline)) int32_t tls_versus_global(int32_t amount) {
    /* Deliberately adjacent: the two loads must not be conflated. */
    tls_counter += amount;
    global_counter += amount;
    return tls_counter - global_counter;
}

__attribute__((noinline)) int32_t tls_indexed(int32_t index, int32_t value) {
    if (index < 0 || index > 3) {
        return -1;
    }
    tls_table[index] += value;
    return tls_table[index];
}

__attribute__((noinline)) int32_t tls_address_is_stable(void) {
    /* Two evaluations in one thread must denote the same object. */
    int32_t *first = &tls_counter;
    int32_t *second = &tls_counter;
    return (first == second) ? 1 : 0;
}
