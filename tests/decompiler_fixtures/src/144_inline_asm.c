#include <stdint.h>

/* Inline assembly is a region the compiler does not model: the decompiler sees
 * instructions with no source-level intent, and the constraints decide which
 * registers are read, written and clobbered. Guarded per architecture with a
 * portable fallback so every lane of the cross-architecture matrix builds. */

__attribute__((noinline)) int32_t asm_add_via_constraints(int32_t left,
                                                          int32_t right) {
#if defined(__x86_64__) || defined(__i386__)
    int32_t result = left;
    __asm__("addl %1, %0" : "+r"(result) : "r"(right) : "cc");
    return result;
#elif defined(__aarch64__)
    int32_t result;
    __asm__("add %w0, %w1, %w2" : "=r"(result) : "r"(left), "r"(right));
    return result;
#elif defined(__arm__)
    int32_t result;
    __asm__("add %0, %1, %2" : "=r"(result) : "r"(left), "r"(right));
    return result;
#else
    return (int32_t)((uint32_t)left + (uint32_t)right);
#endif
}

__attribute__((noinline)) int32_t asm_memory_barrier(int32_t *cell,
                                                     int32_t value) {
    if (cell == 0) {
        return -1;
    }
    *cell = value;
    /* A full compiler barrier: no memory operation may be moved across it. */
    __asm__ __volatile__("" ::: "memory");
    *cell += 1;
    return *cell;
}

__attribute__((noinline)) int32_t builtin_bit_intrinsics(uint32_t value,
                                                         int32_t which) {
    switch (which & 3) {
    case 0:
        /* clz is undefined at zero, so the zero case is spelled out. */
        return (value == 0u) ? 32 : __builtin_clz(value);
    case 1:
        return (value == 0u) ? 32 : __builtin_ctz(value);
    case 2:
        return (int32_t)__builtin_popcount(value);
    default:
        return (int32_t)__builtin_bswap32(value);
    }
}

__attribute__((noinline)) int32_t builtin_overflow_checked(int32_t left,
                                                           int32_t right,
                                                           int32_t *result) {
    if (result == 0) {
        return -1;
    }
    /* Returns 1 on overflow without ever executing signed overflow itself. */
    if (__builtin_add_overflow(left, right, result)) {
        *result = 0;
        return 1;
    }
    return 0;
}
