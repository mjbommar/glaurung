#include <stdint.h>

/* Lambdas and the closure objects they compile to — the most common C++
 * abstraction in modern code, and one this corpus does not cover at all.
 *
 * WHAT A LAMBDA ACTUALLY IS. An unnamed struct holding the captures, plus an
 * `operator()`. Three capture modes produce three different objects:
 *
 *   * capture-by-value   -> the captured object is COPIED into the closure, so
 *                           the closure's field is a distinct storage location
 *                           from the variable it came from;
 *   * capture-by-reference -> the field is a POINTER to the enclosing frame, so
 *                           reads through it must be modelled as memory, not as
 *                           a copy;
 *   * no capture         -> an empty object with a static-like call operator,
 *                           which every compiler inlines away entirely at -O2.
 *
 * A decompiler that folds the by-value copy into a direct read of the original
 * variable produces C that is right until the original is mutated after
 * capture — which is exactly what `capture_then_mutate` does. That is a
 * silent, plausible wrong answer, and it is the reason this fixture exists.
 *
 * At -O0 each closure is a real stack object with a real `operator()` call; at
 * -O2 most collapse to inline arithmetic. Both are worth covering: the -O0 lane
 * tests object recovery and the -O2 lane tests that the collapse is followed.
 *
 * `10_cpp_runtime_shapes` covers vtables, ctors/dtors and RAII;
 * `137_cpp_templates` covers monomorphization; `138_cpp_operators` covers
 * operator overloading on a named class. None of them constructs a closure, and
 * none exercises a capture list. `std::function` is deliberately NOT used here:
 * it would pull in libstdc++ type-erasure and heap allocation, which the
 * corpus's no-libc, no-allocation rule excludes. The hand-written
 * `callable_ref` below is the same indirection with none of the runtime.
 */

/* Capture by value: `base` is copied into the closure. */
extern "C" __attribute__((noinline)) int32_t capture_by_value(int32_t base,
                                                   int32_t count) {
    if (count < 0 || count > 32) {
        return -1;
    }
    auto add_base = [base](int32_t v) { return v + base; };
    int32_t total = 0;
    for (int32_t i = 0; i < count; i++) {
        total += add_base(i);
    }
    return total;
}

/* Capture by reference: the closure holds a pointer into this frame, and the
 * accumulator is mutated through it. */
extern "C" __attribute__((noinline)) int32_t capture_by_reference(int32_t count) {
    if (count < 0 || count > 32) {
        return -1;
    }
    int32_t total = 0;
    auto accumulate = [&total](int32_t v) { total += v * 2; };
    for (int32_t i = 0; i < count; i++) {
        accumulate(i);
    }
    return total;
}

/* THE DISCRIMINATOR. `base` is captured by value and then mutated. A recovery
 * that reads the original variable instead of the closure's copy returns a
 * different number. */
extern "C" __attribute__((noinline)) int32_t capture_then_mutate(int32_t base) {
    auto snapshot = [base](int32_t v) { return v + base; };
    base += 1000;                    /* must NOT affect the closure */
    return snapshot(1) + base;
}

/* Mixed capture: one by value, one by reference, in one closure object. */
extern "C" __attribute__((noinline)) int32_t mixed_capture(int32_t scale, int32_t count) {
    if (count < 0 || count > 32) {
        return -1;
    }
    int32_t total = 0;
    auto step = [scale, &total](int32_t v) { total += v * scale; };
    for (int32_t i = 0; i < count; i++) {
        step(i);
    }
    return total;
}

/* Hand-written type erasure: a function pointer plus an environment pointer,
 * which is what `std::function` is underneath and what a captureless lambda
 * decays to. This is an INDIRECT CALL through a recovered object field. */
struct callable_ref {
    int32_t (*fn)(const void *env, int32_t value);
    const void *env;
};

struct scale_env {
    int32_t factor;
};

static int32_t scale_apply(const void *env, int32_t value) {
    return value * static_cast<const scale_env *>(env)->factor;
}

extern "C" __attribute__((noinline)) int32_t erased_callable(int32_t factor,
                                                  int32_t count) {
    if (count < 0 || count > 32) {
        return -1;
    }
    scale_env env{factor & 7};
    callable_ref call{&scale_apply, &env};
    int32_t total = 0;
    for (int32_t i = 0; i < count; i++) {
        total += call.fn(call.env, i);
    }
    return total;
}

/* CONTROL: the same arithmetic as an ordinary function call, no closure. */
static int32_t add_base_plain(int32_t v, int32_t base) { return v + base; }

extern "C" __attribute__((noinline)) int32_t plain_call_control(int32_t base,
                                                     int32_t count) {
    if (count < 0 || count > 32) {
        return -1;
    }
    int32_t total = 0;
    for (int32_t i = 0; i < count; i++) {
        total += add_base_plain(i, base);
    }
    return total;
}
