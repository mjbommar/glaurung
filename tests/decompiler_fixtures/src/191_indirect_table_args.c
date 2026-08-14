#include <stdint.h>

/* Arguments to a call through a function-pointer table.
 *
 * An indirect call has no single callee to ask which registers it reads, so a
 * dead-code pass with no may-use set for it deletes the argument setup — and
 * the recovered call then passes whatever happens to be in those registers.
 * That output still compiles and still looks plausible; see
 * `docs/design/table-dispatch-arguments-2026-08-12.md`, where a first attempt
 * at repairing it emitted the right ARITY with the wrong VALUES.
 *
 * A call through a *proven* table is different: the table's entries are a
 * complete, relocation-proven callee set, so the registers the call may read
 * are the union over that set. This fixture exists to make both halves of that
 * observable — the arity AND the values.
 *
 * Every entry records the exact arguments it received in the caller's own
 * scratch buffer. `95_function_pointer_table` already covers the value the
 * dispatch RETURNS; a witness catches an argument list that is wrong in a way
 * the returned value happens to hide, which is exactly the failure mode above.
 * The count is kept in the caller's buffer rather than a global so it survives
 * the harness rebuilding one function against extern callees, in the same way
 * `189_effectful_select` counts its side effect.
 *
 * `t191_computed_args` is the NEAR-MISS CONTROL. Its table call passes values
 * this function computed, not the parameters it was handed, so a recovery that
 * names architectural argument registers and lets naming render them as
 * `arg1, arg2` produces well-typed, plausible, WRONG output and is caught here.
 *
 * `t191_direct_control` is the DEGENERACY CONTROL: the same protocol through a
 * DIRECT call, which the ordinary direct-callee recovery already handles. It
 * must keep passing, so a decompiler cannot satisfy this fixture by making
 * every call conservative. */

#define T191_SLOT_A 0
#define T191_SLOT_B 1
#define T191_SLOT_CALLS 2
#define T191_SLOT_WITNESS 3

typedef int32_t (*T191Op)(int32_t *witness, int32_t a, int32_t b);

__attribute__((noinline)) static int32_t t191_add(int32_t *witness, int32_t a, int32_t b) {
    witness[T191_SLOT_A] = a;
    witness[T191_SLOT_B] = b;
    witness[T191_SLOT_CALLS] += 1;
    return (int32_t)((uint32_t)a + (uint32_t)b);
}

__attribute__((noinline)) static int32_t t191_sub(int32_t *witness, int32_t a, int32_t b) {
    witness[T191_SLOT_A] = a;
    witness[T191_SLOT_B] = b;
    witness[T191_SLOT_CALLS] += 1;
    return (int32_t)((uint32_t)a - (uint32_t)b);
}

__attribute__((noinline)) static int32_t t191_and(int32_t *witness, int32_t a, int32_t b) {
    witness[T191_SLOT_A] = a;
    witness[T191_SLOT_B] = b;
    witness[T191_SLOT_CALLS] += 1;
    return a & b;
}

__attribute__((noinline)) static int32_t t191_max(int32_t *witness, int32_t a, int32_t b) {
    witness[T191_SLOT_A] = a;
    witness[T191_SLOT_B] = b;
    witness[T191_SLOT_CALLS] += 1;
    return a > b ? a : b;
}

static T191Op const T191_OPS[4] = {t191_add, t191_sub, t191_and, t191_max};

/* The plain shape. At -O2 the compiler leaves the incoming registers alone
 * where it can and shuffles the rest into place BEFORE the bounds check, so the
 * setup is not adjacent to the call and not inside the guarded arm either. */
__attribute__((noinline)) int32_t t191_dispatch(int32_t *scratch, int32_t which,
                                                int32_t a, int32_t b) {
    int32_t produced;
    if (scratch == 0) {
        return -1;
    }
    scratch[T191_SLOT_A] = 0;
    scratch[T191_SLOT_B] = 0;
    scratch[T191_SLOT_CALLS] = 0;
    if (which < 0 || which >= 4) {
        return -1;
    }
    produced = T191_OPS[which](scratch, a, b);
    scratch[T191_SLOT_WITNESS] = produced;
    return produced;
}

/* NEAR-MISS CONTROL: the arguments are computed here, so passing this
 * function's own parameter registers is a different answer with the same
 * shape. */
__attribute__((noinline)) int32_t t191_computed_args(int32_t *scratch, int32_t which,
                                                     int32_t seed) {
    int32_t produced;
    int32_t left;
    int32_t right;
    if (scratch == 0) {
        return -1;
    }
    scratch[T191_SLOT_A] = 0;
    scratch[T191_SLOT_B] = 0;
    scratch[T191_SLOT_CALLS] = 0;
    if (which < 0 || which >= 4) {
        return -1;
    }
    left = (int32_t)((uint32_t)seed * 3u + 1u);
    right = seed ^ 0x5a;
    produced = T191_OPS[which](scratch, left, right);
    scratch[T191_SLOT_WITNESS] = produced;
    return produced;
}

/* The dispatch loop: the accumulator is carried round the back edge and is the
 * argument of the next call, so the reaching value at the call is not the
 * function's entry value for that register. */
__attribute__((noinline)) int32_t t191_fold(int32_t *scratch, const int32_t *selectors,
                                            int32_t count, int32_t seed) {
    int32_t accumulator = seed;
    int32_t index;
    if (scratch == 0 || selectors == 0 || count < 0 || count > 16) {
        return -1;
    }
    scratch[T191_SLOT_A] = 0;
    scratch[T191_SLOT_B] = 0;
    scratch[T191_SLOT_CALLS] = 0;
    for (index = 0; index < count; ++index) {
        int32_t which = selectors[index];
        if (which < 0 || which >= 4) {
            continue;
        }
        accumulator = T191_OPS[which](scratch, accumulator, index + 1);
    }
    scratch[T191_SLOT_WITNESS] = accumulator;
    return accumulator;
}

/* DEGENERACY CONTROL: one entry, called directly. Nothing about the indirect
 * may-use set may disturb the recovery that already works. */
__attribute__((noinline)) int32_t t191_direct_control(int32_t *scratch, int32_t a,
                                                      int32_t b) {
    int32_t produced;
    if (scratch == 0) {
        return -1;
    }
    scratch[T191_SLOT_A] = 0;
    scratch[T191_SLOT_B] = 0;
    scratch[T191_SLOT_CALLS] = 0;
    produced = t191_add(scratch, a, b);
    scratch[T191_SLOT_WITNESS] = produced;
    return produced;
}
