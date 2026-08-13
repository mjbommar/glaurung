#include <stdint.h>
#include <stdarg.h>

/* A variadic callee: arguments past the prototype are passed by the register
 * save area / overflow area rules, and the callee walks them with va_arg.
 * Default argument promotion means a narrow value arrives as int. */

static int32_t sum_variadic(int32_t count, ...) {
    va_list arguments;
    int32_t total = 0;
    int32_t index;
    if (count < 0 || count > 8) {
        return -1;
    }
    va_start(arguments, count);
    for (index = 0; index < count; ++index) {
        total += va_arg(arguments, int32_t);
    }
    va_end(arguments);
    return total;
}

static int32_t weighted_variadic(int32_t count, ...) {
    va_list arguments;
    int32_t total = 0;
    int32_t index;
    if (count < 0 || count > 8) {
        return -1;
    }
    va_start(arguments, count);
    for (index = 0; index < count; ++index) {
        total += va_arg(arguments, int32_t) * (index + 1);
    }
    va_end(arguments);
    return total;
}

__attribute__((noinline)) int32_t
variadic_three(int32_t a, int32_t b, int32_t c) {
    return sum_variadic(3, a, b, c);
}

__attribute__((noinline)) int32_t
variadic_weighted_four(int32_t a, int32_t b, int32_t c, int32_t d) {
    return weighted_variadic(4, a, b, c, d);
}

__attribute__((noinline)) int32_t variadic_none(void) {
    return sum_variadic(0);
}
