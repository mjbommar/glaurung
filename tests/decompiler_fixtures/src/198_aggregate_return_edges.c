#include <stdint.h>

/* THE BY-VALUE RETURN CLASSES 195 AND 197 LEAVE OUT.
 *
 * `195_by_value_aggregates` covers SysV's INTEGER (8B, `rax`), INTEGER-pair
 * (16B, `rax:rdx`), split-bank (16B, `rax` + `xmm0`) and MEMORY (32B, hidden
 * pointer) classes. `197_homogeneous_float_aggregates` covers the all-SSE
 * classes (16B and 12B) and AAPCS64's homogeneous float aggregates. Between
 * them every aggregate this corpus returns is 8, 12, 16 or 32 bytes, and every
 * one of them fills its registers exactly or overflows to memory at a multiple
 * of eight.
 *
 * The cells they never reach, all of which classify differently:
 *
 *   struct {int32_t a;}           4B   INTEGER  -> the LOW HALF of rax only
 *   struct {uint8_t a,b,c;}       3B   INTEGER  -> three bytes of rax, and a
 *                                                  size that is not a power of
 *                                                  two, so a load of "the
 *                                                  struct" is not one access
 *   struct {int32_t a,b,c;}      12B   INTEGER,INTEGER -> rax:rdx with rdx
 *                                                  HALF used. This is the
 *                                                  integer twin of 197's
 *                                                  `hfa197_trio3f`, and the
 *                                                  corpus has the float half
 *                                                  of that pair and not the
 *                                                  integer half.
 *   union {int64_t; double;}      8B   the class MERGE: SSE meets INTEGER and
 *                                                  INTEGER wins, so this comes
 *                                                  back in `rax` even though
 *                                                  it holds a `double`. Nothing
 *                                                  in the corpus returns a
 *                                                  union at all, and until
 *                                                  2026-08-18 the DWARF reader
 *                                                  could not describe one
 *                                                  either.
 *   struct {int32_t v[2];}        8B   INTEGER  -> rax, but the member is an
 *                                                  ARRAY, which has an extent
 *                                                  and not just an offset.
 *                                                  `dwarf_signatures.rs` used
 *                                                  to decline array members
 *                                                  outright; since 2026-08-18
 *                                                  it describes them, so this
 *                                                  helper is marshalled rather
 *                                                  than reached only through
 *                                                  its wrapper.
 *   struct {int32_t a..e;}       20B   MEMORY, and NOT a multiple of eight —
 *                                                  195's memory case is exactly
 *                                                  32B, so the tail-padding
 *                                                  copy has never been asked
 *                                                  for.
 *
 * As in 195 and 197, the aggregate-returning helpers are exercised THROUGH
 * callers that return `int32_t`. That is not a stylistic choice: `exec_class`
 * in `tools/diff_decompile.py` classifies EVERY aggregate return as
 * `structural` ("aggregate return — not execution-differential"), because
 * `_ctypes_fn` builds a return type with `_scalar_ctype`, which knows only
 * integers and floats. A struct-returning function can therefore never be
 * called by the differential directly, and the only way to observe the ABI is
 * to make a caller's recovered C get it right in order to call its helper at
 * all. Each caller also witnesses the individual members in a caller-owned
 * buffer with DISTINCT coefficients, so recovering the right total from
 * permuted members is caught instead of passing by luck.
 *
 * TWO NEGATIVE CONTROLS:
 *
 *   `agr198_make_i64` returns an `int64_t` — eight bytes, in `rax`, exactly
 *   where `agr198_make_arr2`'s eight-byte struct arrives, and it is NOT an
 *   aggregate. A recovery that classifies by "eight bytes in the result
 *   register" satisfies every positive case here and fails this one. It is also
 *   the only helper in this file the differential can call directly, so it is
 *   declared REQUIRED and gets its own verdict.
 *
 *   `agr198_scalar_control` runs the same arithmetic and the same buffer writes
 *   with no aggregate anywhere, so a recovery that routes everything through
 *   the hidden-pointer path fails it.
 *
 * `seed` is pinned to small exact values by the manifest, so no product
 * overflows and the `double` written into the union is exactly representable —
 * its bit pattern is then a deterministic constant on both sides. */

#define AGR198_SLOT_A 0
#define AGR198_SLOT_B 1
#define AGR198_SLOT_C 2
#define AGR198_SLOT_D 3
#define AGR198_SLOT_E 4

struct agr198_one {    /*  4 bytes: the low half of one register */
    int32_t a;
};

struct agr198_bytes3 { /*  3 bytes: not a power of two, sub-word */
    uint8_t a;
    uint8_t b;
    uint8_t c;
};

struct agr198_trio {   /* 12 bytes: rax:rdx, rdx half used */
    int32_t a;
    int32_t b;
    int32_t c;
};

union agr198_bits {    /*  8 bytes: SSE merged with INTEGER -> INTEGER */
    int64_t i;
    double d;
};

struct agr198_arr2 {   /*  8 bytes, and the member is an ARRAY */
    int32_t v[2];
};

struct agr198_five {   /* 20 bytes: MEMORY, not a multiple of eight */
    int32_t a;
    int32_t b;
    int32_t c;
    int32_t d;
    int32_t e;
};

__attribute__((noinline)) struct agr198_one agr198_make_one(int32_t seed) {
    struct agr198_one s;
    s.a = seed * 3 + 1;
    return s;
}

__attribute__((noinline)) struct agr198_bytes3 agr198_make_bytes3(int32_t seed) {
    struct agr198_bytes3 s;
    s.a = (uint8_t)(seed + 1);
    s.b = (uint8_t)(seed + 2);
    s.c = (uint8_t)(seed * 3);
    return s;
}

__attribute__((noinline)) struct agr198_trio agr198_make_trio(int32_t seed) {
    struct agr198_trio s;
    s.a = seed + 1;
    s.b = seed * 2;
    s.c = seed * 4;
    return s;
}

/* Writes the `double` member and the caller reads the `int64_t` one: the union
 * is a real type pun at the RETURN boundary, and the result is an exact IEEE
 * bit pattern because `seed` is pinned to small integers. */
__attribute__((noinline)) union agr198_bits agr198_make_bits(int32_t seed) {
    union agr198_bits u;
    u.d = (double)(seed * 2 + 1);
    return u;
}

__attribute__((noinline)) struct agr198_arr2 agr198_make_arr2(int32_t seed) {
    struct agr198_arr2 s;
    s.v[0] = seed + 5;
    s.v[1] = seed * 7;
    return s;
}

__attribute__((noinline)) struct agr198_five agr198_make_five(int32_t seed) {
    struct agr198_five s;
    s.a = seed + 1;
    s.b = seed + 2;
    s.c = seed * 3;
    s.d = seed * 5;
    s.e = seed * 7;
    return s;
}

/* CONTROL helper: eight bytes in `rax` that are NOT an aggregate. Directly
 * executable, unlike every other helper in this file. */
__attribute__((noinline)) int64_t agr198_make_i64(int32_t seed) {
    return (int64_t)seed * 7 + 5;
}

__attribute__((noinline)) int32_t agr198_one_roundtrip(int32_t *scratch, int32_t seed) {
    struct agr198_one s;
    if (scratch == 0) {
        return -1;
    }
    s = agr198_make_one(seed);
    scratch[AGR198_SLOT_A] = s.a;
    return s.a * 3;
}

__attribute__((noinline)) int32_t agr198_bytes3_roundtrip(int32_t *scratch, int32_t seed) {
    struct agr198_bytes3 s;
    if (scratch == 0) {
        return -1;
    }
    /* Three bytes: a recovery that copies four (a whole register's low half)
     * picks up whatever sits in the fourth. */
    s = agr198_make_bytes3(seed);
    scratch[AGR198_SLOT_A] = s.a;
    scratch[AGR198_SLOT_B] = s.b;
    scratch[AGR198_SLOT_C] = s.c;
    return (int32_t)s.a + (int32_t)s.b * 3 + (int32_t)s.c * 5;
}

__attribute__((noinline)) int32_t agr198_trio_roundtrip(int32_t *scratch, int32_t seed) {
    struct agr198_trio s;
    if (scratch == 0) {
        return -1;
    }
    /* rdx is HALF occupied: a recovery that assumes a full second eightbyte
     * reads a fourth member that was never stored. */
    s = agr198_make_trio(seed);
    scratch[AGR198_SLOT_A] = s.a;
    scratch[AGR198_SLOT_B] = s.b;
    scratch[AGR198_SLOT_C] = s.c;
    return s.a + s.b * 3 + s.c * 5;
}

__attribute__((noinline)) int32_t agr198_bits_roundtrip(int32_t *scratch, int32_t seed) {
    union agr198_bits u;
    if (scratch == 0) {
        return -1;
    }
    /* The union arrives in `rax`, not in `xmm0`, even though the value written
     * into it was a `double`. Reading the two halves of the bit pattern proves
     * which register it came back in. */
    u = agr198_make_bits(seed);
    scratch[AGR198_SLOT_A] = (int32_t)(u.i & 0xffffffff);
    scratch[AGR198_SLOT_B] = (int32_t)((uint64_t)u.i >> 32);
    return (int32_t)((uint64_t)u.i >> 52);
}

__attribute__((noinline)) int32_t agr198_arr2_roundtrip(int32_t *scratch, int32_t seed) {
    struct agr198_arr2 s;
    if (scratch == 0) {
        return -1;
    }
    s = agr198_make_arr2(seed);
    scratch[AGR198_SLOT_A] = s.v[0];
    scratch[AGR198_SLOT_B] = s.v[1];
    return s.v[0] + s.v[1] * 3;
}

__attribute__((noinline)) int32_t agr198_five_roundtrip(int32_t *scratch, int32_t seed) {
    struct agr198_five s;
    if (scratch == 0) {
        return -1;
    }
    /* MEMORY class at 20 bytes: the hidden return pointer takes the first
     * argument register AND the copy back is not a whole number of eightbytes. */
    s = agr198_make_five(seed);
    scratch[AGR198_SLOT_A] = s.a;
    scratch[AGR198_SLOT_B] = s.b;
    scratch[AGR198_SLOT_C] = s.c;
    scratch[AGR198_SLOT_D] = s.d;
    scratch[AGR198_SLOT_E] = s.e;
    return s.a + s.b * 3 + s.c * 5 + s.d * 7 + s.e * 11;
}

/* CONTROL: eight bytes in `rax` from a scalar. Must not acquire aggregate
 * handling just because its neighbours have it. */
__attribute__((noinline)) int32_t agr198_i64_control(int32_t *scratch, int32_t seed) {
    int64_t v;
    if (scratch == 0) {
        return -1;
    }
    v = agr198_make_i64(seed);
    scratch[AGR198_SLOT_A] = (int32_t)(v & 0xffffffff);
    scratch[AGR198_SLOT_B] = (int32_t)((uint64_t)v >> 32);
    return (int32_t)v * 3;
}

/* CONTROL: no aggregate anywhere, same buffer discipline. */
__attribute__((noinline)) int32_t agr198_scalar_control(int32_t *scratch, int32_t seed) {
    int32_t a;
    int32_t b;
    int32_t c;
    if (scratch == 0) {
        return -1;
    }
    a = seed + 1;
    b = seed * 2;
    c = seed * 4;
    scratch[AGR198_SLOT_A] = a;
    scratch[AGR198_SLOT_B] = b;
    scratch[AGR198_SLOT_C] = c;
    return a + b * 3 + c * 5;
}
