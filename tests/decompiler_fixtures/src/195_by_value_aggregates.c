#include <stdint.h>

/* Aggregates passed and returned BY VALUE, across the SysV classification
 * boundaries.
 *
 * The corpus had no lane for this at all: before this fixture, zero fixtures
 * returned a struct by value, and `RecoveredOutputKind::HiddenReturn` was a
 * declared variant matched in three places and constructed in none — a case the
 * type system knows about and the corpus could never reach.
 *
 * SysV x86-64 classifies a return aggregate by size and field class:
 *
 *   <= 8 bytes, all integer      -> rax
 *   <= 16 bytes, all integer     -> rax:rdx        (TWO registers, one value)
 *   <= 16 bytes, int + double    -> rax + xmm0     (SPLIT ACROSS BANKS)
 *   >  16 bytes                  -> MEMORY: the caller allocates and passes a
 *                                   hidden pointer, every real argument shifts
 *                                   one register right, and the callee returns
 *                                   that pointer in rax
 *
 * Each of those is a different ABI contract, and the last one changes the
 * meaning of every subsequent argument register. A decompiler that treats them
 * uniformly still produces C that compiles.
 *
 * The struct-returning helpers are exercised THROUGH callers that return an
 * `int32_t`, because that is the only way the execution differential can observe
 * them: the harness rebuilds one function at a time against extern callees, so a
 * caller's recovered C has to get the aggregate ABI right to call its helper at
 * all. Each caller also writes the individual fields into the caller's own
 * scratch buffer, so recovering the right total from the wrong fields is caught
 * rather than passing by luck; the fields are combined with DISTINCT
 * coefficients, since a plain sum would hide a swap.
 *
 * `bv195_scalar_control` is the control: an ordinary scalar return that must NOT
 * acquire aggregate handling. Without it, a decompiler that routed everything
 * through the memory-class path would satisfy the rest of the fixture. */

#define BV195_SLOT_A 0
#define BV195_SLOT_B 1
#define BV195_SLOT_C 2
#define BV195_SLOT_D 3

struct bv195_pair {   /* 8 bytes, INTEGER -> rax */
    int32_t a;
    int32_t b;
};

struct bv195_quad {   /* 16 bytes, INTEGER -> rax:rdx */
    int32_t a;
    int32_t b;
    int32_t c;
    int32_t d;
};

struct bv195_mixed {  /* 16 bytes, INTEGER + SSE -> rax + xmm0 */
    int32_t tag;
    double value;
};

struct bv195_big {    /* 32 bytes, MEMORY -> hidden pointer */
    int64_t v[4];
};

__attribute__((noinline)) struct bv195_pair bv195_make_pair(int32_t seed) {
    struct bv195_pair p;
    p.a = seed + 1;
    p.b = seed * 2;
    return p;
}

__attribute__((noinline)) struct bv195_quad bv195_make_quad(int32_t seed) {
    struct bv195_quad q;
    q.a = seed + 1;
    q.b = seed + 2;
    q.c = seed * 3;
    q.d = seed * 5;
    return q;
}

__attribute__((noinline)) struct bv195_mixed bv195_make_mixed(int32_t seed) {
    struct bv195_mixed m;
    m.tag = seed + 7;
    /* Kept exactly representable so the differential compares an exact value
     * rather than an excess-precision artifact. */
    m.value = (double)(seed * 4);
    return m;
}

__attribute__((noinline)) struct bv195_big bv195_make_big(int32_t seed) {
    struct bv195_big b;
    b.v[0] = seed + 1;
    b.v[1] = seed + 2;
    b.v[2] = seed * 3;
    b.v[3] = seed * 5;
    return b;
}

/* A by-value aggregate ARGUMENT, which is the mirror case: an 8-byte struct
 * arrives packed in one register, and the callee must unpack it rather than
 * treating the register as a scalar. */
__attribute__((noinline)) int32_t bv195_consume_pair(struct bv195_pair p) {
    return p.a * 3 + p.b;
}

__attribute__((noinline)) int32_t bv195_pair_roundtrip(int32_t *scratch, int32_t seed) {
    struct bv195_pair p;
    if (scratch == 0) {
        return -1;
    }
    p = bv195_make_pair(seed);
    scratch[BV195_SLOT_A] = p.a;
    scratch[BV195_SLOT_B] = p.b;
    return bv195_consume_pair(p);
}

__attribute__((noinline)) int32_t bv195_quad_roundtrip(int32_t *scratch, int32_t seed) {
    struct bv195_quad q;
    if (scratch == 0) {
        return -1;
    }
    q = bv195_make_quad(seed);
    scratch[BV195_SLOT_A] = q.a;
    scratch[BV195_SLOT_B] = q.b;
    scratch[BV195_SLOT_C] = q.c;
    scratch[BV195_SLOT_D] = q.d;
    /* Distinct coefficients: a field permutation changes this. */
    return q.a + q.b * 3 + q.c * 5 + q.d * 7;
}

__attribute__((noinline)) int32_t bv195_mixed_roundtrip(int32_t *scratch, int32_t seed) {
    struct bv195_mixed m;
    if (scratch == 0) {
        return -1;
    }
    m = bv195_make_mixed(seed);
    scratch[BV195_SLOT_A] = m.tag;
    scratch[BV195_SLOT_B] = (int32_t)m.value;
    /* Reads BOTH halves of a value the ABI split across two register banks. */
    return m.tag * 3 + (int32_t)m.value;
}

__attribute__((noinline)) int32_t bv195_big_roundtrip(int32_t *scratch, int32_t seed) {
    struct bv195_big b;
    if (scratch == 0) {
        return -1;
    }
    /* MEMORY class: the hidden return pointer occupies the first argument
     * register, so `seed` arrives one register later than it otherwise would. */
    b = bv195_make_big(seed);
    scratch[BV195_SLOT_A] = (int32_t)b.v[0];
    scratch[BV195_SLOT_B] = (int32_t)b.v[1];
    scratch[BV195_SLOT_C] = (int32_t)b.v[2];
    scratch[BV195_SLOT_D] = (int32_t)b.v[3];
    return (int32_t)(b.v[0] + b.v[1] * 3 + b.v[2] * 5 + b.v[3] * 7);
}

/* CONTROL: an ordinary scalar return through the same shapes of arithmetic. It
 * must not acquire a hidden pointer or a register pair. */
__attribute__((noinline)) int32_t bv195_scalar_control(int32_t *scratch, int32_t seed) {
    int32_t a;
    int32_t b;
    if (scratch == 0) {
        return -1;
    }
    a = seed + 1;
    b = seed * 2;
    scratch[BV195_SLOT_A] = a;
    scratch[BV195_SLOT_B] = b;
    return a * 3 + b;
}
