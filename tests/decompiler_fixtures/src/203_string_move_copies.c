#include <stdint.h>

/* The x86 STRING MOVE — `rep movsq` — which had no lane in this corpus at all.
 *
 * Every one of the ~200 fixture sources was compiled at -O0 and -O2 under both
 * gcc and clang and the disassembly grepped for the whole family: `movsb`,
 * `movsw`, `movsl` and `movsq` appeared zero times. That silence is why the
 * defect this fixture pins survived. Over the committed amd64 sample corpus the
 * same two mnemonics are the third and fourth largest entries in `lift_x86`'s
 * silent-register-write census — `movsb` 242 occurrences, `movsq` 134 — and an
 * unlifted instruction does not merely lose its semantics. It declares NO
 * register write, so register dataflow concludes RDI and RSI were never touched
 * and whatever they held before the copy flows on into every later reader. Every
 * glibc `memcpy` built on `rep movsq` recovered with both pointers frozen at
 * their pre-loop values.
 *
 * The shape is not exotic and it is not assembly-only: it is what both compilers
 * emit for an ordinary large-aggregate copy in plain C, with no intrinsic, no
 * attribute and no -march. Verified by disassembly, not from memory — at a
 * 384-byte aggregate:
 *
 *   mv203_by_value_wide     gcc -O0, gcc -O2, clang -O0, clang -O2   rep movsq
 *   mv203_local_wide_copy   gcc -O0, gcc -O2                         rep movsq
 *
 * so all four x86-64 lanes carry the instruction and two of them carry it twice.
 * On i386 both become `rep movsl`, which is the one member of the family that
 * DID have an arm — and the arm lifted a single element and left ECX untouched,
 * so a repeated dword copy was modelled as copying exactly four bytes. On armv7
 * and aarch64 the same source compiles to a `memcpy` call, which is the point of
 * keeping the C portable: this is a string-move lane on x86 and an ordinary
 * aggregate-copy lane everywhere else, and every lane must produce the same
 * numbers.
 *
 * EVERYTHING IS 32-BIT ON PURPOSE. The elements could as easily be `uint64_t`,
 * and the copy would still be `rep movsq` — but 64-bit arithmetic on i386 is
 * carried in a register pair, and the i386 lanes would then fail on the
 * register-pair recovery rather than on anything to do with the copy. Making the
 * VALUES 32-bit keeps the i386 lanes about the string move, which is the only
 * architecture where the dword form appears.
 *
 * WHAT MAKES IT DISCRIMINATING. A copy is only observable if something reads
 * more than its first element. Each consumer therefore folds EVERY element with
 * a distinct coefficient and also mixes in the last element separately, so the
 * three ways this can be wrong are three different wrong answers:
 *
 *   * pointers frozen (the defect above)  -> every element reads as element 0
 *   * one pointer stepped, not the other  -> source and destination desync
 *   * the count not drained               -> the copy runs the wrong length
 *
 * A plain sum would hide the first of those whenever the elements happen to be
 * permuted, and returning only element 0 would hide all three.
 *
 * NEGATIVE CONTROLS. `mv203_by_value_narrow` and `mv203_local_narrow_copy` are
 * the same two functions at 16 bytes, which both compilers copy with ordinary
 * `mov` pairs — no string move anywhere in them. `mv203_scalar_control` has no
 * aggregate at all. If a change breaks the wide cases and leaves these three
 * passing, the fault is in the string move; if it breaks all five, it is
 * somewhere general and this fixture is not the evidence. */

#define MV203_WIDE 96  /* 384 bytes: above both compilers' rep-movs threshold */
#define MV203_NARROW 4 /* 16 bytes: below it, in every lane */

struct mv203_wide {
    uint32_t q[MV203_WIDE];
};

struct mv203_narrow {
    uint32_t q[MV203_NARROW];
};

/* A deterministic filler. Integer only, and every element differs from every
 * other: the differential compares exact values, and a repeated element would
 * make a frozen pointer invisible. */
__attribute__((noinline)) void mv203_fill_wide(struct mv203_wide *out, int32_t seed) {
    uint32_t state = (uint32_t)seed + 0x9e3779b9u;
    for (int i = 0; i < MV203_WIDE; i++) {
        state = state * 1664525u + 1013904223u;
        out->q[i] = state;
    }
}

__attribute__((noinline)) void mv203_fill_narrow(struct mv203_narrow *out, int32_t seed) {
    uint32_t state = (uint32_t)seed + 0x9e3779b9u;
    for (int i = 0; i < MV203_NARROW; i++) {
        state = state * 1664525u + 1013904223u;
        out->q[i] = state;
    }
}

/* Distinct coefficients, plus the last element mixed in apart from the fold, so
 * a copy that never advanced its pointers cannot land on the same total. */
__attribute__((noinline)) uint32_t mv203_consume_wide(struct mv203_wide v) {
    uint32_t acc = 0;
    for (int i = 0; i < MV203_WIDE; i++) {
        acc += v.q[i] * (uint32_t)(i + 1);
    }
    return acc ^ (v.q[MV203_WIDE - 1] << 1);
}

__attribute__((noinline)) uint32_t mv203_consume_narrow(struct mv203_narrow v) {
    uint32_t acc = 0;
    for (int i = 0; i < MV203_NARROW; i++) {
        acc += v.q[i] * (uint32_t)(i + 1);
    }
    return acc ^ (v.q[MV203_NARROW - 1] << 1);
}

/* THE STRING MOVE, route one: an aggregate passed BY VALUE. The caller copies
 * the whole struct into the outgoing argument area, and above the threshold both
 * compilers do that with `rep movsq` at both optimisation levels. */
__attribute__((noinline)) uint32_t mv203_by_value_wide(int32_t seed) {
    struct mv203_wide a;
    mv203_fill_wide(&a, seed);
    return mv203_consume_wide(a);
}

/* THE STRING MOVE, route two: a struct ASSIGNMENT between two locals. gcc emits
 * `rep movsq` for this at both levels; clang unrolls it into vector moves, so
 * this function is a string-move lane in two of the four x86-64 lanes and an
 * ordinary copy in the other two. Both must agree. */
__attribute__((noinline)) uint32_t mv203_local_wide_copy(int32_t seed) {
    struct mv203_wide a;
    struct mv203_wide b;
    mv203_fill_wide(&a, seed);
    b = a;
    uint32_t acc = 0;
    for (int i = 0; i < MV203_WIDE; i++) {
        acc += b.q[i] * (uint32_t)(i + 1);
    }
    return acc ^ (b.q[MV203_WIDE - 1] << 1);
}

/* NEGATIVE CONTROL: the by-value route below the threshold. No string move in
 * any lane; a register-pair copy instead. */
__attribute__((noinline)) uint32_t mv203_by_value_narrow(int32_t seed) {
    struct mv203_narrow a;
    mv203_fill_narrow(&a, seed);
    return mv203_consume_narrow(a);
}

/* NEGATIVE CONTROL: the assignment route below the threshold. */
__attribute__((noinline)) uint32_t mv203_local_narrow_copy(int32_t seed) {
    struct mv203_narrow a;
    struct mv203_narrow b;
    mv203_fill_narrow(&a, seed);
    b = a;
    uint32_t acc = 0;
    for (int i = 0; i < MV203_NARROW; i++) {
        acc += b.q[i] * (uint32_t)(i + 1);
    }
    return acc ^ (b.q[MV203_NARROW - 1] << 1);
}

/* NEGATIVE CONTROL: no aggregate at all, so nothing here can route through
 * aggregate copy handling of any kind. */
__attribute__((noinline)) uint32_t mv203_scalar_control(int32_t seed) {
    uint32_t state = (uint32_t)seed + 0x9e3779b9u;
    state = state * 1664525u + 1013904223u;
    return state ^ (state << 1);
}
