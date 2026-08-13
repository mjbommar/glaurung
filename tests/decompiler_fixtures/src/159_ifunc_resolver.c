#include <stdint.h>

/* An STT_GNU_IFUNC symbol is a function whose ADDRESS is computed at load time.
 * The symbol's st_value does not point at a body; it points at a resolver, and
 * the loader calls that resolver during relocation processing and writes the
 * returned address into the GOT slot (R_X86_64_IRELATIVE, applied after all
 * other relocations, before any user code runs). This is how glibc dispatches
 * memcpy/strlen to an AVX2 or SSE2 body, and it is the single most confusing
 * shape in a real .so for a decompiler:
 *
 *   - the call site is an ordinary PLT call, but nothing static points at the
 *     code that will actually run;
 *   - the resolver looks like a leaf function returning a pointer and is
 *     reachable only from a relocation, so a CFG built from call edges leaves
 *     it and both implementations unreferenced (candidate dead code);
 *   - the ifunc alias carries no DWARF subprogram at all - gcc and clang emit
 *     debug info for the resolver and the implementations, never for the alias
 *     - so a DWARF-driven recovery has a name with no body and two bodies with
 *     no callers;
 *   - the resolver runs before the C runtime is initialised, so it may not call
 *     into libc, which is why real ones are tiny and read cpu feature words.
 *
 * Determinism note: BOTH implementations here compute exactly the same value by
 * different instruction sequences (shift versus self-addition), so whichever
 * one the resolver picks, the observable result is identical. Nothing in this
 * fixture can vary between two loads of the same code.
 *
 * The second half is the hand-rolled equivalent: a static function pointer
 * resolved once on first use. Same dispatch semantics, no loader involvement -
 * the contrast is the point.
 */

typedef int32_t (*Ifn159Fn)(int32_t);

static int32_t ifn159_impl_shift(int32_t value) {
    return (int32_t)((uint32_t)value << 1);
}

static int32_t ifn159_impl_add(int32_t value) {
    return (int32_t)((uint32_t)value + (uint32_t)value);
}

/* Selector kept fixed rather than read from cpu feature bits: the harness
 * compares two loads of the same code, so the choice must not depend on the
 * host. A real resolver differs only in where this word comes from. */
static const uint32_t IFN159_FEATURE_WORD = 0x1u;

static Ifn159Fn ifn159_resolve(void);

/* The alias itself: exported as STT_GNU_IFUNC, no DWARF, no body. */
int32_t ifunc_double(int32_t value) __attribute__((ifunc("ifn159_resolve")));

static Ifn159Fn ifn159_resolve(void) {
    if ((IFN159_FEATURE_WORD & 1u) != 0u) {
        return ifn159_impl_shift;
    }
    return ifn159_impl_add;
}

/* Ordinary exported wrapper so the ifunc is exercised through a function that
 * does have DWARF and can carry an execution contract. */
__attribute__((noinline)) int32_t ifunc_call_double(int32_t value) {
    return ifunc_double(value);
}

/* The ifunc must agree with the arithmetic it stands for, for every input. */
__attribute__((noinline)) int32_t ifunc_matches_reference(int32_t value) {
    uint32_t dispatched = (uint32_t)ifunc_double(value);
    uint32_t reference = (uint32_t)value * 2u;
    return (int32_t)(dispatched - reference);
}

/* Repeated dispatch in a bounded loop: every iteration is a PLT call whose
 * target slot was written by the loader, not by the linker. */
__attribute__((noinline)) int32_t
ifunc_fold(const int32_t *values, int32_t count) {
    uint32_t accumulator = 0u;
    int32_t index;
    if (values == 0 || count < 0 || count > 16) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        accumulator += (uint32_t)ifunc_double(values[index]);
    }
    return (int32_t)accumulator;
}

/* Hand-rolled dispatch: a static function pointer, null until the first call,
 * then latched. Cheap to recover in principle - the table is one slot - but the
 * "already resolved?" test is a load-modify-branch that a decompiler tends to
 * render as an unrelated global flag. Latching is idempotent and both targets
 * agree, so repeated calls return identical values. */
static Ifn159Fn ifn159_cached = 0;

__attribute__((noinline)) int32_t ifunc_lazy_double(int32_t value) {
    Ifn159Fn chosen = ifn159_cached;
    if (chosen == 0) {
        chosen = ifn159_resolve();
        ifn159_cached = chosen;
    }
    return chosen(value);
}

/* Loader-resolved and hand-resolved dispatch must agree: 0 for every input. */
__attribute__((noinline)) int32_t ifunc_paths_agree(int32_t value) {
    uint32_t loader_side = (uint32_t)ifunc_double(value);
    uint32_t manual_side = (uint32_t)ifunc_lazy_double(value);
    return (int32_t)(loader_side - manual_side);
}
