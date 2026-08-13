#include <stdint.h>

/* .init_array / .fini_array are entry points nothing calls. The loader walks
 * the arrays after relocation (init) and at dlclose / exit (fini), so these
 * functions have no incoming call edge anywhere in the object - they are
 * reachable only from a pointer table in a data section, and the table entries
 * are R_X86_64_RELATIVE relocations, not symbols.
 *
 * That breaks the two assumptions a decompiler usually makes at once. Function
 * discovery driven by call graph reachability drops the constructors as dead
 * code (a real .so's ctors are where the interesting setup lives - this is the
 * standard place packers and droppers hide work, precisely because a naive
 * analysis starts at exported functions). And the globals the constructor
 * writes look, in the static image, like they still hold their .data
 * initialisers, so any recovery that reads initialised values off disk reports
 * the WRONG constant for every read below.
 *
 * Constructor priorities make the ordering observable: with (101) running
 * before (102), ctor160_order ends at 12 and not 21. Priority lives only in the
 * section name (.init_array.00101), which the linker sorts and then discards,
 * so recovering the order at all means reading the final table order.
 *
 * Determinism: the constructors run exactly once per load and store fixed
 * values (no counters, no addresses), so every exported function below returns
 * the same answer on every call and on every load. The destructor's effect is
 * observable only after unload, so initfini_witness is 0 for the whole run -
 * what it tests is that the store is not proved dead and the .fini_array entry
 * is still recovered.
 */

static int32_t ctor160_ready = -1;
static int32_t ctor160_order = 0;
static int32_t ctor160_table[4] = {0, 0, 0, 0};

/* Exported and volatile so the destructor's store cannot be optimised away. */
volatile int32_t initfini_shutdown_witness = 0;

__attribute__((constructor(101))) static void ctor160_early(void) {
    ctor160_order = 1;
}

__attribute__((constructor(102))) static void ctor160_late(void) {
    /* 1 -> 12 if the priorities were honoured; 2 alone if `early` never ran. */
    ctor160_order = ctor160_order * 10 + 2;
}

__attribute__((constructor)) static void ctor160_init(void) {
    int32_t index;
    for (index = 0; index < 4; ++index) {
        ctor160_table[index] = (index + 1) * 10;
    }
    ctor160_ready = 1;
}

__attribute__((destructor)) static void ctor160_fini(void) {
    ctor160_ready = 0;
    initfini_shutdown_witness = 1;
}

/* 1 once the constructor has run; the on-disk initialiser is -1. */
__attribute__((noinline)) int32_t initfini_ready(void) {
    return ctor160_ready;
}

/* 12: priority 101 then priority 102. */
__attribute__((noinline)) int32_t initfini_order(void) {
    return ctor160_order;
}

/* The table is all zeroes in the image and 10/20/30/40 once loaded. */
__attribute__((noinline)) int32_t initfini_table(int32_t index) {
    if (index < 0 || index > 3) {
        return -1;
    }
    return ctor160_table[index];
}

/* 0 while the object is loaded; the destructor sets it during unload, which no
 * call can observe. */
__attribute__((noinline)) int32_t initfini_witness(void) {
    return initfini_shutdown_witness;
}

/* Constructor-initialised data feeding an ordinary bounded loop, so a wrong
 * constant propagated from the .data image shows up as a wrong sum rather than
 * as a missing symbol. */
__attribute__((noinline)) int32_t
initfini_fold(const int32_t *values, int32_t count) {
    uint32_t accumulator = (uint32_t)ctor160_ready;
    int32_t index;
    if (values == 0 || count < 0 || count > 16) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        accumulator += (uint32_t)values[index] +
                       (uint32_t)ctor160_table[index & 3];
    }
    return (int32_t)accumulator;
}
