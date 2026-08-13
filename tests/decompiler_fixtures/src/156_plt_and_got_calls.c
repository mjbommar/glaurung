#include <stdint.h>

/* In a shared object built -fPIC, WHO the callee is decides the instruction.
 *
 * A call to a default-visibility exported sibling is interposable: the dynamic
 * loader is allowed to rebind it to a definition supplied by another object
 * (LD_PRELOAD, or an earlier library in the global scope), so the call site
 * cannot be a fixed PC-relative branch. It becomes `call plt_step_public@PLT`,
 * a branch into a stub that jumps through the .got.plt slot the loader filled
 * in (lazily, through _dl_runtime_resolve, unless BIND_NOW).
 *
 * A call to an internal-linkage sibling can never be rebound, so it is a plain
 * PC-relative `call` straight at the body.
 *
 * Both call sites look identical in the source and compute the same value, but
 * they have different relocation shapes, and only one of them can be replaced
 * at load time. A decompiler has to (a) not stop at the stub and report a call
 * to `.plt+0x30` or an indirect jump through a GOT address, (b) recover the
 * callee's real name from the PLT/GOT relocation rather than from a direct
 * branch target, and (c) not conflate the two: folding the stub away silently
 * loses the only evidence that one of the calls is interposable. gcc and clang
 * disagree here by default (clang assumes no semantic interposition), so the
 * same source yields two different call shapes with one behaviour.
 */

/* Exported with default visibility: every call to this from inside the object
 * still goes through the PLT under -fPIC. */
__attribute__((noinline)) int32_t plt_step_public(int32_t value) {
    return (int32_t)((uint32_t)value * 3u + 7u);
}

/* Internal linkage: identical arithmetic, unpreemptable, direct call. */
static __attribute__((noinline)) int32_t plt156_step_local(int32_t value) {
    return (int32_t)((uint32_t)value * 3u + 7u);
}

__attribute__((noinline)) int32_t plt_call_interposable(int32_t value) {
    return plt_step_public(value);
}

__attribute__((noinline)) int32_t plt_call_local(int32_t value) {
    return plt156_step_local(value);
}

/* The two paths compute the same thing, so this is 0 for every input unless
 * something interposed the exported symbol. Deterministic, and it forces both
 * call shapes into one function. */
__attribute__((noinline)) int32_t plt_paths_agree(int32_t value) {
    uint32_t through_plt = (uint32_t)plt_call_interposable(value);
    uint32_t direct = (uint32_t)plt_call_local(value);
    return (int32_t)(through_plt - direct);
}

/* Alternating relocation kinds inside one loop body: the odd iterations go
 * through the PLT, the even ones branch directly. */
__attribute__((noinline)) int32_t
plt_fold_calls(const int32_t *values, int32_t count) {
    uint32_t accumulator = 0u;
    int32_t index;
    if (values == 0 || count < 0 || count > 16) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        int32_t stepped;
        if ((index & 1) != 0) {
            stepped = plt_step_public(values[index]);
        } else {
            stepped = plt156_step_local(values[index]);
        }
        accumulator += (uint32_t)stepped;
    }
    return (int32_t)accumulator;
}

/* A call through a pointer to the interposable symbol: taking the address of an
 * exported function in PIC code loads it from the GOT, so the same callee is
 * reached by a third relocation shape (GOT load + indirect call) that must
 * still resolve to the same name. */
__attribute__((noinline)) int32_t plt_call_via_address(int32_t value) {
    int32_t (*indirect)(int32_t) = plt_step_public;
    uint32_t through_pointer = (uint32_t)indirect(value);
    uint32_t through_plt = (uint32_t)plt_step_public(value);
    return (int32_t)(through_pointer - through_plt);
}
