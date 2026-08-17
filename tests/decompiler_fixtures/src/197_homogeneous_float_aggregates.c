#include <stdint.h>

/* Aggregates whose members are ALL floating point — the return class `195` left
 * out, and the one where the two ABIs we test disagree the most.
 *
 * `195_by_value_aggregates` covers SysV's INTEGER (`rax`), INTEGER-pair
 * (`rax:rdx`), split-bank (`rax` + `xmm0`) and MEMORY classes. It has no
 * all-SSE case, so nothing in the corpus returns a value in `xmm0:xmm1` — TWO
 * SSE registers holding ONE value, which is a distinct contract from the split
 * case and from a scalar `double`.
 *
 * The same four shapes are a completely different mechanism on AArch64, and the
 * corpus has no lane for that at all: AAPCS64 returns a *homogeneous float
 * aggregate* (2-4 members, all the same float type) in consecutive SIMD
 * registers, so `{float,float,float,float}` comes back in `s0`-`s3` — four
 * registers, one value — where SysV packs the same struct into two `xmm`s at two
 * floats apiece. A recovery that models "the float result" as a single register
 * is wrong on both, in different ways, and no existing fixture can say so.
 *
 *   struct                     SysV x86-64            AAPCS64
 *   {double,double}      16B   SSE,SSE  -> xmm0:xmm1  HFA(2xdouble) -> d0:d1
 *   {float x4}           16B   SSE,SSE  -> xmm0:xmm1  HFA(4xfloat)  -> s0:s1:s2:s3
 *   {float x3}           12B   SSE,SSE  -> xmm0:xmm1  HFA(3xfloat)  -> s0:s1:s2
 *   {float,int32_t}       8B   INTEGER  -> rax        not an HFA    -> x0
 *
 * The 12-byte case is deliberately not a multiple of the register width: SysV
 * puts `a`,`b` in `xmm0` and `c` alone in the low half of `xmm1`, so a recovery
 * that assumes both eightbytes are full reads a fourth field that does not
 * exist.
 *
 * `hfa197_tagged_control` is the negative that makes the rest mean something: it
 * CONTAINS a float but is not homogeneous, so both ABIs return it in an INTEGER
 * register. A decompiler that routes "aggregate containing floating point" to
 * the SSE bank satisfies every positive case here and fails only this one.
 * `hfa197_scalar_control` is the second negative: an ordinary `double` return
 * occupies `xmm0`/`d0` ALONE and must not acquire a second result register.
 *
 * As in `195`, the aggregate-returning helpers are exercised THROUGH callers
 * that return `int32_t`, because the harness rebuilds one function at a time
 * against extern callees — so a caller's recovered C has to get the return ABI
 * right to call its helper at all. Each caller also witnesses the individual
 * members in a caller-owned buffer with DISTINCT coefficients, so recovering the
 * right total from permuted members is caught rather than passing by luck.
 *
 * Every value is a small integer converted to `float`/`double`, so it is exactly
 * representable in both widths and the differential compares exact values rather
 * than excess-precision artifacts. */

#define HFA197_SLOT_A 0
#define HFA197_SLOT_B 1
#define HFA197_SLOT_C 2
#define HFA197_SLOT_D 3

struct hfa197_pair2d {  /* 16 bytes, SSE,SSE -> xmm0:xmm1 / HFA -> d0:d1 */
    double x;
    double y;
};

struct hfa197_quad4f {  /* 16 bytes, SSE,SSE -> xmm0:xmm1 / HFA -> s0..s3 */
    float a;
    float b;
    float c;
    float d;
};

struct hfa197_trio3f {  /* 12 bytes: xmm1 is HALF used / HFA -> s0..s2 */
    float a;
    float b;
    float c;
};

struct hfa197_tagged {  /* 8 bytes, NOT homogeneous -> rax / x0 */
    float value;
    int32_t tag;
};

__attribute__((noinline)) struct hfa197_pair2d hfa197_make_pair2d(int32_t seed) {
    struct hfa197_pair2d p;
    p.x = (double)(seed + 1);
    p.y = (double)(seed * 2);
    return p;
}

__attribute__((noinline)) struct hfa197_quad4f hfa197_make_quad4f(int32_t seed) {
    struct hfa197_quad4f q;
    q.a = (float)(seed + 1);
    q.b = (float)(seed + 2);
    q.c = (float)(seed * 3);
    q.d = (float)(seed * 5);
    return q;
}

__attribute__((noinline)) struct hfa197_trio3f hfa197_make_trio3f(int32_t seed) {
    struct hfa197_trio3f t;
    t.a = (float)(seed + 1);
    t.b = (float)(seed * 2);
    t.c = (float)(seed * 4);
    return t;
}

__attribute__((noinline)) struct hfa197_tagged hfa197_make_tagged(int32_t seed) {
    struct hfa197_tagged t;
    t.value = (float)(seed + 3);
    t.tag = seed * 2;
    return t;
}

/* An ordinary scalar `double` return: ONE result register, no pair. */
__attribute__((noinline)) double hfa197_make_scalar(int32_t seed) {
    return (double)(seed * 6 + 1);
}

/* A homogeneous float aggregate as an ARGUMENT, which is the mirror case: the
 * members arrive in consecutive SIMD registers rather than packed into one. */
__attribute__((noinline)) int32_t hfa197_consume_pair2d(struct hfa197_pair2d p) {
    return (int32_t)p.x * 3 + (int32_t)p.y;
}

__attribute__((noinline)) int32_t hfa197_pair2d_roundtrip(int32_t *scratch, int32_t seed) {
    struct hfa197_pair2d p;
    if (scratch == 0) {
        return -1;
    }
    p = hfa197_make_pair2d(seed);
    scratch[HFA197_SLOT_A] = (int32_t)p.x;
    scratch[HFA197_SLOT_B] = (int32_t)p.y;
    /* Reads BOTH halves of a value the ABI split across two SSE registers. */
    return hfa197_consume_pair2d(p);
}

__attribute__((noinline)) int32_t hfa197_quad4f_roundtrip(int32_t *scratch, int32_t seed) {
    struct hfa197_quad4f q;
    if (scratch == 0) {
        return -1;
    }
    q = hfa197_make_quad4f(seed);
    scratch[HFA197_SLOT_A] = (int32_t)q.a;
    scratch[HFA197_SLOT_B] = (int32_t)q.b;
    scratch[HFA197_SLOT_C] = (int32_t)q.c;
    scratch[HFA197_SLOT_D] = (int32_t)q.d;
    /* Distinct coefficients: a member permutation changes this. On SysV `a`,`b`
     * share one xmm and `c`,`d` share the other, so a half-register mix-up is
     * observable here and nowhere else in the corpus. */
    return (int32_t)q.a + (int32_t)q.b * 3 + (int32_t)q.c * 5 + (int32_t)q.d * 7;
}

__attribute__((noinline)) int32_t hfa197_trio3f_roundtrip(int32_t *scratch, int32_t seed) {
    struct hfa197_trio3f t;
    if (scratch == 0) {
        return -1;
    }
    /* 12 bytes: the second eightbyte is HALF occupied. A recovery that assumes a
     * full pair reads a fourth member that was never stored. */
    t = hfa197_make_trio3f(seed);
    scratch[HFA197_SLOT_A] = (int32_t)t.a;
    scratch[HFA197_SLOT_B] = (int32_t)t.b;
    scratch[HFA197_SLOT_C] = (int32_t)t.c;
    return (int32_t)t.a + (int32_t)t.b * 3 + (int32_t)t.c * 5;
}

/* CONTROL: contains a float, but is NOT homogeneous, so both ABIs return it in
 * an INTEGER register. A decompiler that routes "aggregate containing floating
 * point" to the SSE bank passes every case above and fails exactly here. */
__attribute__((noinline)) int32_t hfa197_tagged_control(int32_t *scratch, int32_t seed) {
    struct hfa197_tagged t;
    if (scratch == 0) {
        return -1;
    }
    t = hfa197_make_tagged(seed);
    scratch[HFA197_SLOT_A] = (int32_t)t.value;
    scratch[HFA197_SLOT_B] = t.tag;
    return (int32_t)t.value * 3 + t.tag;
}

/* CONTROL: a plain `double` return occupies ONE result register. It must not
 * acquire a second one just because the fixture around it returns pairs. */
__attribute__((noinline)) int32_t hfa197_scalar_control(int32_t *scratch, int32_t seed) {
    double v;
    if (scratch == 0) {
        return -1;
    }
    v = hfa197_make_scalar(seed);
    scratch[HFA197_SLOT_A] = (int32_t)v;
    scratch[HFA197_SLOT_B] = (int32_t)v * 2;
    return (int32_t)v * 3 + 1;
}
