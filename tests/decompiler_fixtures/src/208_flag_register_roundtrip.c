#include <stdint.h>

/* An instruction the lifter does not model, whose destination register is
 * nevertheless READ afterwards.
 *
 * THE DEFECT. `Op::opaque` builds `Op::Intrinsic { ins: [], outs: [],
 * reads_mem: true, writes_mem: true }` and its doc calls it
 * "maximally-conservative". That is true of memory and FALSE of registers:
 * `outs: []` is not an absence of information, it is a positive claim that no
 * register is written. `use_def::defs_uses` returns no definition, so
 * `ssa::write_regs` places no phi and never bumps the destination's version,
 * and the value live BEFORE the instruction flows past it into every later
 * reader. `memory_ssa` maps the same op to `unknown_effects(true, true)` and
 * clobbers every region — assume-everything for memory, assume-nothing for
 * registers, from one op.
 *
 * The consequence is worse than a wrong value. A destination that nothing
 * defines is read as an INCOMING ARGUMENT, so the recovered prototype grows
 * parameters the function never had. A one-argument function is reported with
 * three. That moves `type_match` (argument correspondence), `byte_match` (the
 * recompiled signature) and the def-use census simultaneously.
 *
 * WHY THE FLAG REGISTER. The obvious reproduction is `rdtsc` or `cpuid`, and
 * both are unusable here: a timestamp is not deterministic and CPUID is not
 * portable. Saving and restoring the flag register is unmodelled in exactly the
 * same way, is deterministic, and exists on every architecture we test —
 * `pushfq`/`popfq` on x86-64, `mrs`/`msr nzcv` on AArch64, `mrs`/`msr cpsr` on
 * ARM32 — with a portable fallback so no lane loses the fixture.
 *
 * `205_x87_long_double` covers the same root cause through the x87 stack, which
 * is 99.997% of the corpus-wide occurrences. This covers it through a
 * GENERAL-PURPOSE register, which is where the phantom-parameter symptom
 * appears, and no other fixture reaches it.
 *
 * Every function returns a value derived only from its arguments, so a correct
 * recovery is checkable by execution; the arity is checkable by reading the
 * recovered prototype.
 */

static inline uint64_t save_flags(void) {
#if defined(__x86_64__)
    uint64_t flags;
    __asm__ __volatile__("pushfq\n\tpopq %0" : "=r"(flags)::"memory");
    return flags;
#elif defined(__i386__)
    uint32_t flags;
    __asm__ __volatile__("pushfl\n\tpopl %0" : "=r"(flags)::"memory");
    return flags;
#elif defined(__aarch64__)
    uint64_t flags;
    __asm__ __volatile__("mrs %0, nzcv" : "=r"(flags));
    return flags;
#elif defined(__arm__)
    uint32_t flags;
    __asm__ __volatile__("mrs %0, cpsr" : "=r"(flags));
    return flags;
#else
    return 0;
#endif
}

/* The measurement. `seed * K` lands in the same register class the flag save
 * writes; if that write is invisible to dataflow, the multiply's result flows
 * past it and the mask below reads a value the machine never produced. The
 * flags themselves are masked away entirely, so the ANSWER is deterministic on
 * every target while the instruction remains unmodelled. */
__attribute__((noinline)) int64_t flags_do_not_leak(int64_t seed) {
    int64_t product = seed * 2654435761LL;
    uint64_t flags = save_flags();
    /* Discard every architecturally-defined bit: the result depends only on
     * `seed`, but only if the flag read did not clobber the product. */
    return product + (int64_t)(flags & 0);
}

/* One argument in, one argument out, with an unmodelled instruction between
 * them. A recovered prototype with more than one parameter is the phantom-
 * parameter defect. */
__attribute__((noinline)) int64_t single_argument_survives(int64_t value) {
    (void)save_flags();
    return value + 1;
}

/* The unmodelled instruction sits inside a loop, so a stale value propagates
 * across iterations rather than once. */
__attribute__((noinline)) int64_t accumulate_across_barrier(int32_t count) {
    int64_t total = 0;
    if (count < 0 || count > 32) {
        return -1;
    }
    for (int32_t i = 0; i < count; i++) {
        total += (int64_t)i * 3;
        (void)save_flags();
        total ^= 0x11;
    }
    return total;
}

/* CONTROL: the identical shape with the unmodelled instruction removed. If this
 * fails, the defect is in the arithmetic and not in the effect model. */
__attribute__((noinline)) int64_t control_without_barrier(int64_t seed) {
    int64_t product = seed * 2654435761LL;
    return product + 0;
}
