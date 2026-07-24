/* 08_indirect_dispatch.c
 *
 * Indirect-call / target-recovery fixture. A dispatcher selects a handler from
 * an OPERATIONS TABLE (array of function pointers) indexed by a tag argument and
 * returns the handler's result. Every handler returns a UNIQUE combination of
 * its inputs, so an execution-differential test (original vs. recompiled
 * decompilation) catches a mis-recovered call target the instant `dispatch`
 * routes a tag to the wrong handler.
 *
 * Targets review #8 (indirect / target-call recovery). The property under test:
 * a DIRECT call must resolve to its named callee, while a genuinely INDIRECT
 * call must stay an explicit indirect call whose computed target expression is a
 * real table lookup (`ops[tag]`), never a fabricated/guessed direct callee. The
 * table and all handlers live in this translation unit so it links standalone.
 *
 * Differential vs. structural:
 *   - dispatch(), dispatch_switch(), tail_dispatch(): DIFFERENTIAL. Pure int
 *     functions with unique per-path constants; drivable by an int-diff gate.
 *   - apply(): STRUCTURAL. It takes a caller-supplied function pointer, so it
 *     cannot be driven by scalar ints alone; the assertion is that the callback
 *     parameter is preserved as an indirect call through the parameter, not
 *     inlined or bound to a fabricated callee.
 *
 * Keep every handler pure (no globals, no memory) and deterministic.
 */
#include <stdint.h>

/* Function-pointer typedef for a binary integer handler. */
typedef int (*binop_fn)(int, int);

/* --- handlers: each returns a distinct combination of a and b ----------- */

static int h_add(int a, int b) { return a + b + 100; }
static int h_sub(int a, int b) { return a - b + 200; }
static int h_mul(int a, int b) { return a * b + 300; }
static int h_xor(int a, int b) { return (a ^ b) + 400; }
static int h_max(int a, int b) { return (a > b ? a : b) + 500; }

/* The OPERATIONS TABLE: an array of function pointers indexed by tag. A correct
 * decompilation recovers `ops[tag]` as the indirect target expression. */
static binop_fn ops[5] = { h_add, h_sub, h_mul, h_xor, h_max };

/* Table-driven dispatch. `int dispatch(int tag, int a, int b)` selects a handler
 * via an indirect call through ops[tag] and returns its result. The bounds guard
 * returns a unique sentinel so an out-of-range tag stays deterministic. */
int dispatch(int tag, int a, int b) {
    if (tag < 0 || tag >= 5)
        return -1;                 /* unique out-of-range sentinel */
    return ops[tag](a, b);         /* genuine indirect call: target is ops[tag] */
}

/* The same selection expressed as a switch over direct calls. A compiler may or
 * may not lower this to a jump table; either way each arm is a DIRECT call to a
 * named callee, and the returns must match dispatch() arm-for-arm. */
int dispatch_switch(int tag, int a, int b) {
    switch (tag) {
        case 0:  return h_add(a, b);
        case 1:  return h_sub(a, b);
        case 2:  return h_mul(a, b);
        case 3:  return h_xor(a, b);
        case 4:  return h_max(a, b);
        default: return -1;
    }
}

/* Indirect tail call: the selected handler's result is returned directly, giving
 * the exact tail-call shape (jmp through a table slot) that a decompiler must
 * render as an indirect call in return position, not as a fabricated direct one. */
int tail_dispatch(int tag, int a, int b) {
    if (tag < 0 || tag >= 5)
        return -1;
    return ops[tag](a, b);         /* tail position: often lowered to an indirect jmp */
}

/* Callback-parameter function. STRUCTURAL: `cb` is supplied by the caller, so
 * this cannot be exercised by scalar ints through the differential gate. The
 * assertion is that `cb(x)` stays an indirect call through the parameter. */
int apply(int (*cb)(int), int x) {
    return cb(x) + 1;
}
