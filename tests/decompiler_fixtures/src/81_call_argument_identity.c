#include <stdint.h>

/* Two call arguments computed from the SAME scratch register, in the identical
 * `lea -0x1(%rax)` form, with the register redefined between them.
 *
 * At -O0 GCC emits:
 *     mov  -0x24(%rbp),%eax     ; depth
 *     lea  -0x1(%rax),%ecx      ; 4th argument = depth - 1
 *     mov  -0x4(%rbp),%eax      ; split        <-- %eax redefined
 *     lea  -0x1(%rax),%edx      ; 3rd argument = split - 1
 *
 * The use at the first `lea` must bind to the earlier definition. Binding it to
 * the later one collapses both arguments to `split - 1` and silently loses
 * `depth`. Reduced from 36_quicksort, where the lost argument was the recursion
 * depth bound, so the sort terminated early and returned an unsorted array.
 */

__attribute__((noinline)) int32_t
argument_sink(int32_t a, int32_t b, int32_t c, int32_t d) {
    return a * 1000 + b * 100 + c * 10 + d;
}

__attribute__((noinline)) int32_t
two_decrements_one_scratch(const int32_t *values, int32_t low, int32_t high,
                           int32_t depth) {
    int32_t split;
    if (values == 0) {
        return -1;
    }
    split = values[0] + low + high;
    return argument_sink(0, low, split - 1, depth - 1);
}
