#include <stdint.h>

/* sizeof does not evaluate its operand (the sole exception being a VLA), so a
 * call written inside sizeof is never emitted. The result is a compile-time
 * constant of type size_t. */

/* Exported rather than static: `sizeof` never evaluates the call below, so a
 * static definition would be unreferenced and clang rejects that under -Werror.
 * External linkage forces it to be emitted while leaving the point intact. */
__attribute__((noinline)) int32_t sizeof_probe_sets_flag(int32_t *flag) {
    if (flag == 0) {
        return -1;
    }
    *flag = 1;
    return 0;
}

__attribute__((noinline)) int32_t
sizeof_does_not_evaluate(int32_t *flag) {
    if (flag == 0) {
        return -1;
    }
    *flag = 0;
    /* The call is not invoked; only its return type is inspected, so the flag
     * stays 0. */
    return (int32_t)sizeof(sizeof_probe_sets_flag(flag)) * 10 + *flag;
}

__attribute__((noinline)) int32_t sizeof_array_versus_pointer(void) {
    int32_t array[8];
    int32_t *pointer = array;
    /* sizeof(array) is the whole object; sizeof(pointer) is one address. The
     * element-count division is written only for the array, because both
     * compilers reject `sizeof(pointer) / sizeof(element)` outright -- the
     * gotcha this documents is now a diagnostic, so the sizes are compared
     * directly instead. */
    return (int32_t)(sizeof(array) / sizeof(array[0])) * 100 +
           (int32_t)sizeof(pointer);
}

__attribute__((noinline)) int32_t sizeof_after_decay(const int32_t values[8]) {
    /* A parameter declared as an array is really a pointer. `sizeof(values)`
     * would prove it but is a hard error under -Werror on both compilers, so
     * the decay is demonstrated by arithmetic instead: advancing the parameter
     * by one steps one element, exactly as a pointer does, and the declared
     * bound 8 has no effect on it at all. */
    const int32_t *stepped;
    if (values == 0) {
        return -1;
    }
    stepped = values + 1;
    return (int32_t)(stepped - values) * 100 + (int32_t)sizeof(values[0]);
}

__attribute__((noinline)) int32_t sizeof_vla_is_evaluated(int32_t count) {
    if (count < 1 || count > 16) {
        return -1;
    }
    {
        int32_t scratch[count];
        scratch[0] = count;
        /* This sizeof IS a runtime computation. */
        return (int32_t)(sizeof(scratch) / sizeof(scratch[0])) + scratch[0];
    }
}
