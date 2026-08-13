#include <stdint.h>

/* One SHA-256 compression over a single 512-bit block.  A 64-entry constant
 * table in read-only data, a message schedule with four rotations per step,
 * and eight rotating working registers: this is the densest constant-and-
 * rotation recovery case in the corpus. */

static const uint32_t SHA256_K[64] = {
    0x428A2F98u, 0x71374491u, 0xB5C0FBCFu, 0xE9B5DBA5u, 0x3956C25Bu,
    0x59F111F1u, 0x923F82A4u, 0xAB1C5ED5u, 0xD807AA98u, 0x12835B01u,
    0x243185BEu, 0x550C7DC3u, 0x72BE5D74u, 0x80DEB1FEu, 0x9BDC06A7u,
    0xC19BF174u, 0xE49B69C1u, 0xEFBE4786u, 0x0FC19DC6u, 0x240CA1CCu,
    0x2DE92C6Fu, 0x4A7484AAu, 0x5CB0A9DCu, 0x76F988DAu, 0x983E5152u,
    0xA831C66Du, 0xB00327C8u, 0xBF597FC7u, 0xC6E00BF3u, 0xD5A79147u,
    0x06CA6351u, 0x14292967u, 0x27B70A85u, 0x2E1B2138u, 0x4D2C6DFCu,
    0x53380D13u, 0x650A7354u, 0x766A0ABBu, 0x81C2C92Eu, 0x92722C85u,
    0xA2BFE8A1u, 0xA81A664Bu, 0xC24B8B70u, 0xC76C51A3u, 0xD192E819u,
    0xD6990624u, 0xF40E3585u, 0x106AA070u, 0x19A4C116u, 0x1E376C08u,
    0x2748774Cu, 0x34B0BCB5u, 0x391C0CB3u, 0x4ED8AA4Au, 0x5B9CCA4Fu,
    0x682E6FF3u, 0x748F82EEu, 0x78A5636Fu, 0x84C87814u, 0x8CC70208u,
    0x90BEFFFAu, 0xA4506CEBu, 0xBEF9A3F7u, 0xC67178F2u};

static uint32_t rotate_right(uint32_t value, uint32_t amount) {
    return (value >> amount) | (value << (32u - amount));
}

__attribute__((noinline)) uint32_t
sha256_compress_block(const uint32_t *block, uint32_t *state_out) {
    uint32_t schedule[64];
    uint32_t a, b, c, d, e, f, g, h;
    int32_t step;
    if (block == 0 || state_out == 0) {
        return 0;
    }
    for (step = 0; step < 16; ++step) {
        schedule[step] = block[step];
    }
    for (step = 16; step < 64; ++step) {
        uint32_t s0 = rotate_right(schedule[step - 15], 7) ^
                      rotate_right(schedule[step - 15], 18) ^
                      (schedule[step - 15] >> 3);
        uint32_t s1 = rotate_right(schedule[step - 2], 17) ^
                      rotate_right(schedule[step - 2], 19) ^
                      (schedule[step - 2] >> 10);
        schedule[step] = schedule[step - 16] + s0 + schedule[step - 7] + s1;
    }
    a = 0x6A09E667u;
    b = 0xBB67AE85u;
    c = 0x3C6EF372u;
    d = 0xA54FF53Au;
    e = 0x510E527Fu;
    f = 0x9B05688Cu;
    g = 0x1F83D9ABu;
    h = 0x5BE0CD19u;
    for (step = 0; step < 64; ++step) {
        uint32_t big1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^
                        rotate_right(e, 25);
        uint32_t choose = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + big1 + choose + SHA256_K[step] + schedule[step];
        uint32_t big0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^
                        rotate_right(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = big0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    state_out[0] = 0x6A09E667u + a;
    state_out[1] = 0xBB67AE85u + b;
    state_out[2] = 0x3C6EF372u + c;
    state_out[3] = 0xA54FF53Au + d;
    state_out[4] = 0x510E527Fu + e;
    state_out[5] = 0x9B05688Cu + f;
    state_out[6] = 0x1F83D9ABu + g;
    state_out[7] = 0x5BE0CD19u + h;
    return state_out[0] ^ state_out[7];
}
