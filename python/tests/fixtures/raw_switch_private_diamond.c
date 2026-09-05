#include <stdint.h>

/* A real raw dispatch loop whose first arm contains a private diamond. The
 * deliberately non-trivial arithmetic keeps both sides as CFG blocks on ARM
 * rather than allowing the compiler to replace the branch with one conditional
 * instruction. Keeping the arm call-free also preserves GCC's duplicated loop
 * latch, which is what forces the production raw-loop representation. */
__attribute__((noinline, optimize("no-if-conversion", "no-if-conversion2")))
int32_t raw_switch_private_diamond(const uint8_t *ops, int32_t count) {
    int32_t acc = 0;
    if (ops == 0 || count < 0 || count > 64) {
        return -1;
    }
    for (int32_t i = 0; i < count; ++i) {
        switch (ops[i] & 7) {
        case 0:
            if (acc < 7) {
                acc = (acc * 3) + 1;
                acc += acc >> 3;
                acc ^= 0x1357;
            } else {
                acc = (acc * 5) - 2;
                acc -= acc >> 2;
                acc ^= 0x2468;
            }
            break;
        case 1: acc += 2; break;
        case 2: acc ^= 0x55; break;
        case 3: return acc - 4;
        case 4: acc += 8; break;
        case 5: acc -= 8; break;
        case 6: acc = -acc; break;
        default: acc = 0; break;
        }
    }
    return acc;
}
