#include <stdint.h>

/* Visibility is the knob that decides whether a symbol reaches .dynsym at all,
 * and therefore how code and data inside a shared object address themselves.
 *
 * A default-visibility global variable defined in this object is still
 * preemptable: another object earlier in the lookup scope may define the same
 * name, and an executable that links against this library gets a copy
 * relocation. So -fPIC code cannot reach it PC-relatively; it loads the
 * object's address out of the GOT first (`mov sym@GOTPCREL(%rip),%rax` then a
 * load through %rax) - two memory accesses to read one int.
 *
 * A hidden symbol can never be preempted and is not exported at all, so the
 * compiler addresses it with a single PC-relative access (`mov sym(%rip),%eax`)
 * and calls hidden functions directly rather than through the PLT.
 *
 * This is a decompiler problem in three ways. The GOT-indirect load looks like
 * a pointer dereference of a pointer variable that does not exist in the
 * source, so a naive recovery invents one and reports `*(*got_slot)` where the
 * source says `bias`. The name is only recoverable from the R_X86_64_GLOB_DAT /
 * GOTPCREL relocation, not from the instruction. And a hidden function has no
 * dynamic symbol at all, so its name survives only in .symtab, which a stripped
 * object does not have - the same call is `vis157_hidden_helper` here and an
 * anonymous sub_XXXX after `strip`.
 */

/* Default visibility: exported, preemptable, reached through the GOT. */
int32_t vis_public_bias = 11;

/* Hidden: absent from .dynsym, reached PC-relatively. */
__attribute__((visibility("hidden"))) int32_t vis157_hidden_bias = 5;

/* Hidden function: direct call, no PLT entry, no dynamic symbol. */
__attribute__((visibility("hidden"))) __attribute__((noinline)) int32_t
vis157_hidden_helper(int32_t value) {
    return (int32_t)((uint32_t)value ^ 0x5a5au);
}

/* Same body, default visibility: exported, so the sibling call below is an
 * interposable PLT call. */
__attribute__((noinline)) int32_t vis_public_helper(int32_t value) {
    return (int32_t)((uint32_t)value ^ 0x5a5au);
}

/* Writes both globals: one store through a GOT-loaded address, one store to a
 * PC-relative address. The two are kept complementary so the sum is a constant
 * 100 for every input, which no overflow can perturb (|clamped| <= 100). */
__attribute__((noinline)) int32_t vis_set_biases(int32_t value) {
    int32_t clamped = value;
    if (clamped < -100) {
        clamped = -100;
    }
    if (clamped > 100) {
        clamped = 100;
    }
    vis_public_bias = clamped;
    vis157_hidden_bias = 100 - clamped;
    return vis_public_bias + vis157_hidden_bias;
}

/* Reads them back through the two different addressing modes. */
__attribute__((noinline)) int32_t vis_read_bias(int32_t selector) {
    if (selector == 0) {
        return vis_public_bias;
    }
    if (selector == 1) {
        return vis157_hidden_bias;
    }
    return (int32_t)((uint32_t)vis_public_bias + (uint32_t)vis157_hidden_bias);
}

/* Both call shapes in one body. The helpers are identical, so the difference is
 * 0 for every input and the verdict depends only on whether both calls were
 * recovered as calls to the right thing. */
__attribute__((noinline)) int32_t vis_call_both(int32_t value) {
    uint32_t hidden = (uint32_t)vis157_hidden_helper(value);
    uint32_t exported = (uint32_t)vis_public_helper(value);
    return (int32_t)(hidden - exported);
}

/* A loop whose body touches a GOT-addressed global, a PC-relative global and a
 * hidden call: at -O2 the GOT load is hoisted out of the loop, which is exactly
 * the shape that tempts a recovery to invent a loop-invariant pointer local. */
__attribute__((noinline)) int32_t
vis_fold_with_biases(const int32_t *values, int32_t count) {
    uint32_t accumulator = 0u;
    int32_t index;
    if (values == 0 || count < 0 || count > 16) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        uint32_t item = (uint32_t)vis157_hidden_helper(values[index]);
        accumulator += item + (uint32_t)vis_public_bias +
                       (uint32_t)vis157_hidden_bias;
    }
    return (int32_t)accumulator;
}
