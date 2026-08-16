#include <stdint.h>

/* Loads held across a store to a DISJOINT slot of the same frame object.
 *
 * `copy_prop` records a single-use load and folds it into its one reader. At
 * every `Stmt::Store` it used to drop every pending load unconditionally,
 * because "the store may alias". Measured over this corpus at -O0 and -O2 (732
 * C/C++ lanes, 10,051 functions), 1,989 of those dropped loads had a reader
 * waiting in the same straight-line run, and 1,308 of them were a store and a
 * load at CONSTANT, NON-OVERLAPPING offsets of the same named frame object.
 * Only 8 pairs genuinely overlapped. The evidence needed to tell those apart is
 * already in the AST -- `Expr::StackAddr { object }`, a literal displacement,
 * and the widths `Stmt::Store { size }` and `Expr::Deref { size }` already
 * carry -- so no instruction identity has to be threaded to keep them.
 *
 * The risk being guarded is the expensive one. Folding a load across a store
 * that DOES alias moves a read past a write and yields C that compiles, runs,
 * and returns a different number. Every function here is executed and
 * differentiated against the original, and the three controls exist to fail if
 * the disjointness test is ever loosened:
 *
 *   dfs196_spill_web        POSITIVE. 48 locals live across two mixing phases,
 *                           so the allocator spills them and the phases read
 *                           and write distinct constant slots of one frame
 *                           object. This is the shape the 1,308 came from.
 *   dfs196_alias_control    CONTROL. The store goes through a pointer that
 *                           really does point into the same array. Nothing
 *                           proves non-aliasing, so the load must not move.
 *   dfs196_indexed_control  CONTROL. The written slot is a runtime value, so no
 *                           constant displacement exists to compare.
 *   dfs196_overlap_control  CONTROL. A 2-byte write and a 4-byte read that
 *                           share bytes, at constant displacements -- exactly
 *                           the case the range test must REJECT rather than
 *                           accept. Reached through a union so the overlap is
 *                           real storage reuse, not a discardable type pun. */

#define DFS196_N 8

__attribute__((noinline)) int32_t dfs196_spill_web(int32_t *scratch, int32_t seed) {
    uint32_t base = (uint32_t)seed * 2654435761u + 0x9E3779B1u;
    uint32_t total = 0u;
    if (scratch == 0) {
        return -1;
    }
    uint32_t s00 = base * 1103515245u + 1u;
    uint32_t s01 = base * 1103515283u + 8u;
    uint32_t s02 = base * 1103515321u + 15u;
    uint32_t s03 = base * 1103515359u + 22u;
    uint32_t s04 = base * 1103515397u + 29u;
    uint32_t s05 = base * 1103515435u + 36u;
    uint32_t s06 = base * 1103515473u + 43u;
    uint32_t s07 = base * 1103515511u + 50u;
    uint32_t s08 = base * 1103515549u + 57u;
    uint32_t s09 = base * 1103515587u + 64u;
    uint32_t s10 = base * 1103515625u + 71u;
    uint32_t s11 = base * 1103515663u + 78u;
    uint32_t s12 = base * 1103515701u + 85u;
    uint32_t s13 = base * 1103515739u + 92u;
    uint32_t s14 = base * 1103515777u + 99u;
    uint32_t s15 = base * 1103515815u + 106u;
    uint32_t s16 = base * 1103515853u + 113u;
    uint32_t s17 = base * 1103515891u + 120u;
    uint32_t s18 = base * 1103515929u + 127u;
    uint32_t s19 = base * 1103515967u + 134u;
    uint32_t s20 = base * 1103516005u + 141u;
    uint32_t s21 = base * 1103516043u + 148u;
    uint32_t s22 = base * 1103516081u + 155u;
    uint32_t s23 = base * 1103516119u + 162u;
    uint32_t s24 = base * 1103516157u + 169u;
    uint32_t s25 = base * 1103516195u + 176u;
    uint32_t s26 = base * 1103516233u + 183u;
    uint32_t s27 = base * 1103516271u + 190u;
    uint32_t s28 = base * 1103516309u + 197u;
    uint32_t s29 = base * 1103516347u + 204u;
    uint32_t s30 = base * 1103516385u + 211u;
    uint32_t s31 = base * 1103516423u + 218u;
    uint32_t s32 = base * 1103516461u + 225u;
    uint32_t s33 = base * 1103516499u + 232u;
    uint32_t s34 = base * 1103516537u + 239u;
    uint32_t s35 = base * 1103516575u + 246u;
    uint32_t s36 = base * 1103516613u + 253u;
    uint32_t s37 = base * 1103516651u + 260u;
    uint32_t s38 = base * 1103516689u + 267u;
    uint32_t s39 = base * 1103516727u + 274u;
    uint32_t s40 = base * 1103516765u + 281u;
    uint32_t s41 = base * 1103516803u + 288u;
    uint32_t s42 = base * 1103516841u + 295u;
    uint32_t s43 = base * 1103516879u + 302u;
    uint32_t s44 = base * 1103516917u + 309u;
    uint32_t s45 = base * 1103516955u + 316u;
    uint32_t s46 = base * 1103516993u + 323u;
    uint32_t s47 = base * 1103517031u + 330u;

    /* Every local is live across both phases, so the allocator has to
     * spill most of them to the frame; the phases then read and write
     * distinct constant slots of that one spill object. */
    s00 = (s00 + (s11 ^ (s19 >> 1u))) + 0x1234u;
    s01 = (s01 + (s12 ^ (s20 >> 2u))) + 0xb06bu;
    s02 = (s02 + (s13 ^ (s21 >> 3u))) + 0x14ea2u;
    s03 = (s03 + (s14 ^ (s22 >> 4u))) + 0x1ecd9u;
    s04 = (s04 + (s15 ^ (s23 >> 5u))) + 0x28b10u;
    s05 = (s05 + (s16 ^ (s24 >> 6u))) + 0x32947u;
    s06 = (s06 + (s17 ^ (s25 >> 7u))) + 0x3c77eu;
    s07 = (s07 + (s18 ^ (s26 >> 1u))) + 0x465b5u;
    s08 = (s08 + (s19 ^ (s27 >> 2u))) + 0x503ecu;
    s09 = (s09 + (s20 ^ (s28 >> 3u))) + 0x5a223u;
    s10 = (s10 + (s21 ^ (s29 >> 4u))) + 0x6405au;
    s11 = (s11 + (s22 ^ (s30 >> 5u))) + 0x6de91u;
    s12 = (s12 + (s23 ^ (s31 >> 6u))) + 0x77cc8u;
    s13 = (s13 + (s24 ^ (s32 >> 7u))) + 0x81affu;
    s14 = (s14 + (s25 ^ (s33 >> 1u))) + 0x8b936u;
    s15 = (s15 + (s26 ^ (s34 >> 2u))) + 0x9576du;
    s16 = (s16 + (s27 ^ (s35 >> 3u))) + 0x9f5a4u;
    s17 = (s17 + (s28 ^ (s36 >> 4u))) + 0xa93dbu;
    s18 = (s18 + (s29 ^ (s37 >> 5u))) + 0xb3212u;
    s19 = (s19 + (s30 ^ (s38 >> 6u))) + 0xbd049u;
    s20 = (s20 + (s31 ^ (s39 >> 7u))) + 0xc6e80u;
    s21 = (s21 + (s32 ^ (s40 >> 1u))) + 0xd0cb7u;
    s22 = (s22 + (s33 ^ (s41 >> 2u))) + 0xdaaeeu;
    s23 = (s23 + (s34 ^ (s42 >> 3u))) + 0xe4925u;
    s24 = (s24 + (s35 ^ (s43 >> 4u))) + 0xee75cu;
    s25 = (s25 + (s36 ^ (s44 >> 5u))) + 0xf8593u;
    s26 = (s26 + (s37 ^ (s45 >> 6u))) + 0x1023cau;
    s27 = (s27 + (s38 ^ (s46 >> 7u))) + 0x10c201u;
    s28 = (s28 + (s39 ^ (s47 >> 1u))) + 0x116038u;
    s29 = (s29 + (s40 ^ (s00 >> 2u))) + 0x11fe6fu;
    s30 = (s30 + (s41 ^ (s01 >> 3u))) + 0x129ca6u;
    s31 = (s31 + (s42 ^ (s02 >> 4u))) + 0x133addu;
    s32 = (s32 + (s43 ^ (s03 >> 5u))) + 0x13d914u;
    s33 = (s33 + (s44 ^ (s04 >> 6u))) + 0x14774bu;
    s34 = (s34 + (s45 ^ (s05 >> 7u))) + 0x151582u;
    s35 = (s35 + (s46 ^ (s06 >> 1u))) + 0x15b3b9u;
    s36 = (s36 + (s47 ^ (s07 >> 2u))) + 0x1651f0u;
    s37 = (s37 + (s00 ^ (s08 >> 3u))) + 0x16f027u;
    s38 = (s38 + (s01 ^ (s09 >> 4u))) + 0x178e5eu;
    s39 = (s39 + (s02 ^ (s10 >> 5u))) + 0x182c95u;
    s40 = (s40 + (s03 ^ (s11 >> 6u))) + 0x18caccu;
    s41 = (s41 + (s04 ^ (s12 >> 7u))) + 0x196903u;
    s42 = (s42 + (s05 ^ (s13 >> 1u))) + 0x1a073au;
    s43 = (s43 + (s06 ^ (s14 >> 2u))) + 0x1aa571u;
    s44 = (s44 + (s07 ^ (s15 >> 3u))) + 0x1b43a8u;
    s45 = (s45 + (s08 ^ (s16 >> 4u))) + 0x1be1dfu;
    s46 = (s46 + (s09 ^ (s17 >> 5u))) + 0x1c8016u;
    s47 = (s47 + (s10 ^ (s18 >> 6u))) + 0x1d1e4du;

    s00 = (s00 * 3u) ^ (s05 + s23);
    s01 = (s01 * 3u) ^ (s06 + s24);
    s02 = (s02 * 3u) ^ (s07 + s25);
    s03 = (s03 * 3u) ^ (s08 + s26);
    s04 = (s04 * 3u) ^ (s09 + s27);
    s05 = (s05 * 3u) ^ (s10 + s28);
    s06 = (s06 * 3u) ^ (s11 + s29);
    s07 = (s07 * 3u) ^ (s12 + s30);
    s08 = (s08 * 3u) ^ (s13 + s31);
    s09 = (s09 * 3u) ^ (s14 + s32);
    s10 = (s10 * 3u) ^ (s15 + s33);
    s11 = (s11 * 3u) ^ (s16 + s34);
    s12 = (s12 * 3u) ^ (s17 + s35);
    s13 = (s13 * 3u) ^ (s18 + s36);
    s14 = (s14 * 3u) ^ (s19 + s37);
    s15 = (s15 * 3u) ^ (s20 + s38);
    s16 = (s16 * 3u) ^ (s21 + s39);
    s17 = (s17 * 3u) ^ (s22 + s40);
    s18 = (s18 * 3u) ^ (s23 + s41);
    s19 = (s19 * 3u) ^ (s24 + s42);
    s20 = (s20 * 3u) ^ (s25 + s43);
    s21 = (s21 * 3u) ^ (s26 + s44);
    s22 = (s22 * 3u) ^ (s27 + s45);
    s23 = (s23 * 3u) ^ (s28 + s46);
    s24 = (s24 * 3u) ^ (s29 + s47);
    s25 = (s25 * 3u) ^ (s30 + s00);
    s26 = (s26 * 3u) ^ (s31 + s01);
    s27 = (s27 * 3u) ^ (s32 + s02);
    s28 = (s28 * 3u) ^ (s33 + s03);
    s29 = (s29 * 3u) ^ (s34 + s04);
    s30 = (s30 * 3u) ^ (s35 + s05);
    s31 = (s31 * 3u) ^ (s36 + s06);
    s32 = (s32 * 3u) ^ (s37 + s07);
    s33 = (s33 * 3u) ^ (s38 + s08);
    s34 = (s34 * 3u) ^ (s39 + s09);
    s35 = (s35 * 3u) ^ (s40 + s10);
    s36 = (s36 * 3u) ^ (s41 + s11);
    s37 = (s37 * 3u) ^ (s42 + s12);
    s38 = (s38 * 3u) ^ (s43 + s13);
    s39 = (s39 * 3u) ^ (s44 + s14);
    s40 = (s40 * 3u) ^ (s45 + s15);
    s41 = (s41 * 3u) ^ (s46 + s16);
    s42 = (s42 * 3u) ^ (s47 + s17);
    s43 = (s43 * 3u) ^ (s00 + s18);
    s44 = (s44 * 3u) ^ (s01 + s19);
    s45 = (s45 * 3u) ^ (s02 + s20);
    s46 = (s46 * 3u) ^ (s03 + s21);
    s47 = (s47 * 3u) ^ (s04 + s22);

    /* Distinct positional weight: a slot read one store too late, or
     * two slots swapped, changes the total. */
    total = total * 31u + s00;
    total = total * 31u + s01;
    total = total * 31u + s02;
    total = total * 31u + s03;
    total = total * 31u + s04;
    total = total * 31u + s05;
    total = total * 31u + s06;
    total = total * 31u + s07;
    total = total * 31u + s08;
    total = total * 31u + s09;
    total = total * 31u + s10;
    total = total * 31u + s11;
    total = total * 31u + s12;
    total = total * 31u + s13;
    total = total * 31u + s14;
    total = total * 31u + s15;
    total = total * 31u + s16;
    total = total * 31u + s17;
    total = total * 31u + s18;
    total = total * 31u + s19;
    total = total * 31u + s20;
    total = total * 31u + s21;
    total = total * 31u + s22;
    total = total * 31u + s23;
    total = total * 31u + s24;
    total = total * 31u + s25;
    total = total * 31u + s26;
    total = total * 31u + s27;
    total = total * 31u + s28;
    total = total * 31u + s29;
    total = total * 31u + s30;
    total = total * 31u + s31;
    total = total * 31u + s32;
    total = total * 31u + s33;
    total = total * 31u + s34;
    total = total * 31u + s35;
    total = total * 31u + s36;
    total = total * 31u + s37;
    total = total * 31u + s38;
    total = total * 31u + s39;
    total = total * 31u + s40;
    total = total * 31u + s41;
    total = total * 31u + s42;
    total = total * 31u + s43;
    total = total * 31u + s44;
    total = total * 31u + s45;
    total = total * 31u + s46;
    total = total * 31u + s47;
    scratch[0] = (int32_t)total;
    scratch[1] = (int32_t)s00;
    return (int32_t)total;
}

/* CONTROL: `p` genuinely points into `a`, so the store through it changes what
 * a later read of `a[3]` must see. Folding a pending load past this store
 * returns the pre-store value, and the differential catches it. */
__attribute__((noinline)) int32_t dfs196_alias_control(int32_t *scratch, int32_t seed) {
    int32_t a[DFS196_N];
    int32_t *p;
    int32_t i;
    int32_t before;
    if (scratch == 0) {
        return -1;
    }
    for (i = 0; i < DFS196_N; i++) {
        a[i] = seed + i;
    }
    p = &a[3];
    before = a[3];
    *p = before + 0x1000;
    scratch[0] = a[3];
    /* Reads the same slot on both sides of the store, with distinct weights. */
    return a[3] * 3 + before;
}

/* CONTROL: the written slot is chosen at runtime, so there is no constant
 * displacement to compare against the pending load's. */
__attribute__((noinline)) int32_t dfs196_indexed_control(int32_t *scratch, int32_t seed) {
    int32_t a[DFS196_N];
    int32_t i;
    int32_t k;
    int32_t before;
    if (scratch == 0) {
        return -1;
    }
    for (i = 0; i < DFS196_N; i++) {
        a[i] = seed * 2 + i;
    }
    k = seed & (DFS196_N - 1);
    before = a[5];
    a[k] = before + 0x777;
    scratch[0] = a[5];
    /* When k == 5 the two reads of a[5] differ. */
    return a[5] * 3 + before;
}

union dfs196_overlap {
    int32_t word[2];
    struct {
        int16_t lo;
        int16_t hi;
    } half[2];
};

/* CONTROL: a 2-byte write inside the 4 bytes a later read covers. Both
 * displacements are constant, so this is the pair the range test has to call
 * overlapping. */
__attribute__((noinline)) int32_t dfs196_overlap_control(int32_t *scratch, int32_t seed) {
    union dfs196_overlap u;
    int32_t before;
    if (scratch == 0) {
        return -1;
    }
    u.word[0] = seed;
    u.word[1] = seed + 1;
    before = u.word[0];
    u.half[0].hi = (int16_t)(seed + 5);
    scratch[0] = u.word[0];
    /* `u.half[0].hi` is the upper half of `u.word[0]`, so this read must see
     * the new value, not `before`. */
    return u.word[0] * 3 + before + u.word[1] * 7;
}
