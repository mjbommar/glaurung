#include <stdint.h>
#include <stdatomic.h>

/* C11 atomics lower to lock-prefixed read-modify-write instructions and
 * compare-exchange retry loops. The memory order argument constrains
 * reordering without computing anything, so it is invisible in the data flow
 * and visible only in which barriers are emitted. */

__attribute__((noinline)) int32_t atomic_increment(int32_t start, int32_t times) {
    atomic_int cell;
    int32_t index;
    if (times < 0 || times > 16) {
        return -1;
    }
    atomic_init(&cell, start);
    for (index = 0; index < times; ++index) {
        atomic_fetch_add_explicit(&cell, 1, memory_order_relaxed);
    }
    return atomic_load_explicit(&cell, memory_order_acquire);
}

__attribute__((noinline)) int32_t
atomic_compare_exchange_loop(int32_t start, int32_t target) {
    atomic_int cell;
    int32_t expected = start;
    int32_t attempts = 0;
    atomic_init(&cell, start);
    /* The weak form may fail spuriously, so the retry edge is real control
     * flow that must survive. */
    while (!atomic_compare_exchange_weak_explicit(
               &cell, &expected, target, memory_order_acq_rel,
               memory_order_relaxed) &&
           attempts < 64) {
        attempts += 1;
    }
    return atomic_load_explicit(&cell, memory_order_seq_cst) * 10 + attempts;
}

__attribute__((noinline)) int32_t atomic_exchange_and_or(int32_t seed) {
    atomic_int cell;
    int32_t previous;
    atomic_init(&cell, seed);
    previous = atomic_exchange_explicit(&cell, seed ^ 0x5A5A, memory_order_acq_rel);
    atomic_fetch_or_explicit(&cell, 1, memory_order_release);
    return previous ^ atomic_load_explicit(&cell, memory_order_acquire);
}

__attribute__((noinline)) int32_t atomic_flag_round_trip(int32_t seed) {
    atomic_flag flag = ATOMIC_FLAG_INIT;
    int32_t first = atomic_flag_test_and_set_explicit(&flag, memory_order_acquire);
    int32_t second = atomic_flag_test_and_set_explicit(&flag, memory_order_acquire);
    atomic_flag_clear_explicit(&flag, memory_order_release);
    return (first ? 1 : 0) * 10 + (second ? 1 : 0) + (seed & 0);
}
