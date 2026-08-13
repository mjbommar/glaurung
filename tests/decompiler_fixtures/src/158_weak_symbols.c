#include <stdint.h>

/* Weak binding is the ELF mechanism behind every "optional dependency" idiom:
 * pthread stubs in libc, __gcov_dump hooks, plugin callbacks a host may or may
 * not provide. Two distinct shapes share the keyword.
 *
 * A weak DEFINITION (STB_WEAK, defined here) is a real body that any strong
 * definition of the same name silently displaces at link or load time. It looks
 * exactly like a normal function in the disassembly; the only trace that it is
 * displaceable is the st_info binding byte in the symbol table.
 *
 * A weak REFERENCE (STB_WEAK, undefined) is a symbol this object mentions but
 * nobody defines. It is not a link error - the loader simply resolves it to
 * address 0, and correct code has to test it before use. That test is the
 * interesting shape: `if (&sym)` on a weak undefined symbol is NOT the
 * tautology the same text would be for an ordinary symbol, so the compiler must
 * not fold it, and a decompiler must not fold it either. In PIC code the test
 * reads a GOT slot the loader wrote 0 into, which decompiles as a null check on
 * a pointer whose origin is a relocation rather than any assignment - if that
 * check is dropped as dead, the recovered code dereferences a null pointer the
 * moment the symbol IS supplied.
 *
 * On this build nothing defines wk158_absent_bias / wk158_absent_scale, so
 * every guarded path here is not taken and the results are constant across
 * loads. What the gate measures is whether the guard itself survived.
 */

/* Weak definition, exported: a strong definition elsewhere would replace it. */
__attribute__((weak)) int32_t weak_scale(int32_t value) {
    return (int32_t)((uint32_t)value * 2u);
}

/* Weak data definition, exported. */
__attribute__((weak)) int32_t weak_shared_bias = 21;

/* Weak references, deliberately never defined anywhere in the corpus: the
 * loader binds both to 0. The names carry the fixture number so that no other
 * translation unit can accidentally satisfy them. */
extern int32_t wk158_absent_bias __attribute__((weak));
extern int32_t wk158_absent_scale(int32_t value) __attribute__((weak));

/* Uses the weak definitions directly. Note what is NOT written here: a
 * `if (weak_scale != 0)` guard, because gcc rejects that under -Wall as an
 * always-true comparison once it can see the definition in this translation
 * unit - it treats a weak DEFINITION as non-null even though a strong
 * definition may displace it. Only a weak REFERENCE (below) can be tested in
 * source. The shape here is still distinct: a call to a weak, exported,
 * interposable function, and a load of weak data through the GOT. */
__attribute__((noinline)) int32_t weak_defined_probe(int32_t value) {
    uint32_t scaled = (uint32_t)weak_scale(value);
    return (int32_t)(scaled + (uint32_t)weak_shared_bias);
}

/* The guarded paths are unreachable on this build (both weak references are
 * unresolved), so the result is `value` for every input. A recovery that drops
 * either guard produces code that calls through address 0 as soon as the
 * symbols are supplied - and a recovery that turns the guard into an
 * unconditional true changes the answer here, immediately. */
__attribute__((noinline)) int32_t weak_absent_probe(int32_t value) {
    uint32_t result = (uint32_t)value;
    if (&wk158_absent_bias != 0) {
        result += (uint32_t)wk158_absent_bias;
    }
    if (wk158_absent_scale != 0) {
        result = (uint32_t)wk158_absent_scale((int32_t)result);
    }
    return (int32_t)result;
}

/* Present-or-absent selected at run time by an argument, so both the taken and
 * the untaken weak tests appear in one control-flow graph. */
__attribute__((noinline)) int32_t weak_dispatch(int32_t value, int32_t use_absent) {
    if (use_absent != 0) {
        if (wk158_absent_scale != 0) {
            return wk158_absent_scale(value);
        }
        return -1;
    }
    return weak_scale(value);
}

/* A weak-guarded call inside a bounded loop: the check is loop-invariant, so at
 * -O2 it is hoisted and the loop is duplicated or the branch is sunk, and the
 * recovered shape has to keep the two versions consistent. */
__attribute__((noinline)) int32_t
weak_fold(const int32_t *values, int32_t count) {
    uint32_t accumulator = (uint32_t)weak_shared_bias;
    int32_t index;
    if (values == 0 || count < 0 || count > 16) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        if (wk158_absent_scale != 0) {
            accumulator += (uint32_t)wk158_absent_scale(values[index]);
        } else {
            accumulator += (uint32_t)weak_scale(values[index]);
        }
    }
    return (int32_t)accumulator;
}
