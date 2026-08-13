/* 138_cpp_operators.cpp
 *
 * Operator overloading turns ordinary-looking syntax into calls. `a + b` on a
 * class type is a function call with a hidden `this` or two by-value arguments;
 * a conversion operator inserts a call where the source shows no call at all.
 */
#include <stdint.h>

namespace {

class Fixed {
public:
    int32_t raw;

    explicit Fixed(int32_t value) : raw(value) {}

    Fixed operator+(const Fixed &other) const {
        return Fixed(static_cast<int32_t>(
            static_cast<uint32_t>(raw) + static_cast<uint32_t>(other.raw)));
    }
    Fixed operator*(const Fixed &other) const {
        return Fixed(static_cast<int32_t>(
            (static_cast<int64_t>(raw) * static_cast<int64_t>(other.raw)) >> 16));
    }
    Fixed &operator+=(const Fixed &other) {
        raw = static_cast<int32_t>(static_cast<uint32_t>(raw) +
                                   static_cast<uint32_t>(other.raw));
        return *this;
    }
    bool operator<(const Fixed &other) const { return raw < other.raw; }
    int32_t operator[](int32_t index) const { return (raw >> (index & 15)) & 1; }
    /* An implicit conversion: appears as no call in the source. */
    operator int32_t() const { return raw >> 16; }
};

}  // namespace

extern "C" int32_t cpp_operator_arithmetic(int32_t a, int32_t b) {
    Fixed left(a);
    Fixed right(b);
    Fixed sum = left + right;
    Fixed product = left * right;
    return sum.raw ^ product.raw;
}

extern "C" int32_t cpp_operator_compound(int32_t seed, int32_t steps) {
    Fixed value(seed);
    Fixed step(1 << 16);
    if (steps < 0 || steps > 16) {
        return -1;
    }
    for (int32_t index = 0; index < steps; ++index) {
        value += step;
    }
    return value.raw;
}

extern "C" int32_t cpp_operator_conversion(int32_t a, int32_t b) {
    Fixed left(a);
    Fixed right(b);
    /* Both operands convert to int32_t through the conversion operator. */
    int32_t widened = left + 0;
    int32_t compared = (left < right) ? 1 : 0;
    return widened * 10 + compared + left[3];
}
