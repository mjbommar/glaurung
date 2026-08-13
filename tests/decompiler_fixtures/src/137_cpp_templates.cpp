/* 137_cpp_templates.cpp
 *
 * Templates are monomorphized: one source body becomes several distinct
 * functions whose code differs only by operand width and operation. They are
 * near-clones in the binary, mangled to different symbols, and a decompiler must
 * neither merge them nor treat them as unrelated.
 */
#include <stdint.h>

namespace {

template <typename T>
T accumulate_range(const T *values, int32_t count, T seed) {
    T total = seed;
    for (int32_t index = 0; index < count; ++index) {
        total = static_cast<T>(total + values[index]);
    }
    return total;
}

template <typename T>
int32_t count_above(const T *values, int32_t count, T threshold) {
    int32_t hits = 0;
    for (int32_t index = 0; index < count; ++index) {
        if (values[index] > threshold) {
            hits += 1;
        }
    }
    return hits;
}

/* A non-type template parameter: the bound is baked into each instantiation. */
template <int32_t Stride>
int32_t strided_sum(const int32_t *values, int32_t count) {
    int32_t total = 0;
    for (int32_t index = 0; index < count; index += Stride) {
        total += values[index];
    }
    return total;
}

}  // namespace

extern "C" int32_t cpp_template_int32(const int32_t *values, int32_t count) {
    if (values == 0 || count < 0 || count > 16) {
        return -1;
    }
    return accumulate_range<int32_t>(values, count, 0);
}

extern "C" int32_t cpp_template_int16(const int32_t *values, int32_t count) {
    int16_t narrowed[16];
    if (values == 0 || count < 0 || count > 16) {
        return -1;
    }
    for (int32_t index = 0; index < count; ++index) {
        narrowed[index] = static_cast<int16_t>(values[index]);
    }
    /* A distinct instantiation: 16-bit arithmetic wraps differently. */
    return accumulate_range<int16_t>(narrowed, count, 0);
}

extern "C" int32_t cpp_template_uint8(const int32_t *values, int32_t count) {
    uint8_t narrowed[16];
    if (values == 0 || count < 0 || count > 16) {
        return -1;
    }
    for (int32_t index = 0; index < count; ++index) {
        narrowed[index] = static_cast<uint8_t>(values[index]);
    }
    return accumulate_range<uint8_t>(narrowed, count, 0);
}

extern "C" int32_t cpp_template_predicate(const int32_t *values, int32_t count,
                                          int32_t threshold) {
    if (values == 0 || count < 0 || count > 16) {
        return -1;
    }
    return count_above<int32_t>(values, count, threshold);
}

extern "C" int32_t cpp_template_nontype(const int32_t *values, int32_t count,
                                        int32_t which) {
    if (values == 0 || count < 0 || count > 16) {
        return -1;
    }
    /* Two instantiations with the stride folded in as a constant. */
    return (which & 1) ? strided_sum<1>(values, count)
                       : strided_sum<2>(values, count);
}
