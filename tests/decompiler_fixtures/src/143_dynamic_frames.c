#include <stdint.h>
#include <alloca.h>

/* alloca moves the stack pointer at runtime, so the frame has no fixed size and
 * locals below it are addressed through a saved base. __attribute__((cleanup))
 * generates a destructor-like call on every exit path, including early returns,
 * which is control flow the source never spells out. */

static void record_cleanup(int32_t *slot) {
    *slot += 1000;
}

__attribute__((noinline)) int32_t alloca_dynamic_frame(int32_t count,
                                                       int32_t seed) {
    int32_t *scratch;
    int32_t index;
    int32_t total = 0;
    if (count < 1 || count > 16) {
        return -1;
    }
    scratch = (int32_t *)alloca((size_t)count * sizeof(int32_t));
    for (index = 0; index < count; ++index) {
        scratch[index] = seed + index;
    }
    for (index = 0; index < count; ++index) {
        total += scratch[index];
    }
    return total;
}

__attribute__((noinline)) int32_t alloca_in_loop(int32_t rounds, int32_t width) {
    int32_t total = 0;
    int32_t round;
    if (rounds < 0 || rounds > 4 || width < 1 || width > 8) {
        return -1;
    }
    for (round = 0; round < rounds; ++round) {
        /* Each iteration extends the frame further; it is released once, at
         * function exit, not per iteration. */
        int32_t *chunk = (int32_t *)alloca((size_t)width * sizeof(int32_t));
        int32_t index;
        for (index = 0; index < width; ++index) {
            chunk[index] = round * width + index;
        }
        total += chunk[width - 1];
    }
    return total;
}

__attribute__((noinline)) int32_t cleanup_on_every_exit(int32_t *observed,
                                                        int32_t selector) {
    if (observed == 0) {
        return -1;
    }
    *observed = 0;
    {
        int32_t guarded __attribute__((cleanup(record_cleanup))) = 0;
        guarded = selector;
        if (selector & 1) {
            return guarded; /* cleanup still runs before returning */
        }
        if (selector & 2) {
            return guarded * 2;
        }
    }
    return selector * 3;
}
