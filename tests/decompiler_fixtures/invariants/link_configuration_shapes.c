/* Shapes that stay IDENTICAL as a source interface while the LINK AND CODEGEN
 * configuration around them changes completely.
 *
 * The execution-differential corpus in `tests/decompiler_fixtures/` varies the
 * SOURCE and holds the build fixed: every one of its artifacts is built
 * `gcc|clang -shared -fPIC -g -O{0,2} -w`, so every one is an ELF `DYN` with a
 * PLT, a GOT, an `.eh_frame`, no entry point worth the name, and no `main`.
 * Real binaries are mostly executables, and an executable differs from that
 * baseline in ways that touch every stage of recovery: where the image is
 * loaded, whether calls go through a PLT at all, whether a frame pointer
 * exists, whether unwind tables exist, and whether every frame carries a
 * canary.
 *
 * This file is therefore deliberately dull as source. Its job is to be the
 * SAME five interfaces compiled ten different ways, so that a property that
 * holds in one configuration and not another isolates the configuration as the
 * cause. Each function is `noinline` and has its address taken through a
 * `volatile` function pointer, which pins the ABI-level interface: GCC cannot
 * apply IPA-SRA, constant propagation or cloning to a function whose address
 * escapes, so a recovered arity that moves between configurations is the
 * decompiler moving, not the compiler.
 *
 * It defines BOTH a `main` and five default-visibility functions, so the exact
 * same translation unit links as a shared object (the functions are exported)
 * and as an executable (there is an entry point). Nothing about the source is
 * conditional on the configuration.
 */

#include <stddef.h>

#if defined(__GNUC__)
/* `used` survives -flto's whole-program view; `noinline` keeps the boundary. */
#define BC_KEEP __attribute__((noinline, used))
#else
#define BC_KEEP
#endif

/* Observable sink, so `main` cannot be optimised into `return 0`. */
volatile long bc_sink;

/* An escape hatch for a stack address. Storing a frame array's address here
 * forces the array to be materialised on the stack in EVERY configuration:
 * without it, -O2 scalarises `bc_buffer_and_scalars` completely (verified: the
 * function compiles to seventeen instructions and touches no stack at all),
 * which would make both the frame-disjointness property and the canary
 * property vacuous at -O2 and -Os. It is also what makes
 * `-fstack-protector-strong` actually insert a guard: the heuristic protects
 * functions with a real local array, and there is no array to protect once the
 * optimiser has removed it. */
unsigned char *volatile bc_escape;

/* 1. More parameters than any mainstream ABI passes in registers, so the tail
 * arrives on the stack. The count is a claim about the ABI, and the ABI does
 * not change when the image becomes position-dependent or statically linked.
 * A recovered arity that moves across those axes is recovering the prologue,
 * not the interface. */
BC_KEEP long bc_many_parameters(long a, long b, long c, long d,
                                long e, long f, long g, long h)
{
    return a + (b * 2) + (c * 3) + (d * 4) + (e * 5) + (f * 6) + (g * 7) + (h * 8);
}

/* 2. A frame array with scalars around it. Two configurations attack this from
 * opposite sides: `-fomit-frame-pointer` removes the register the slot naming
 * is anchored to, and `-fstack-protector-strong` inserts a canary slot at the
 * top of the frame precisely because an array is present. Under both, the
 * declared slots must still tile disjointly, and the canary must not be
 * mistaken for part of the interface. */
BC_KEEP long bc_buffer_and_scalars(const unsigned char *in, unsigned long n)
{
    unsigned char scratch[64];
    long first = 0, second = 0, third = 0;
    unsigned long i;

    bc_escape = scratch;
    for (i = 0; i < n && i < sizeof scratch; i++) {
        scratch[i] = in[i];
        first += scratch[i];
    }
    second = first * 3;
    third = second - (long)i;
    return first + second + third;
}

/* 3. A pointer walk. In a `-shared`/PIE build the loop's code is reached
 * through PC-relative addressing; in `-no-pie` it is absolute; in `-static`
 * there is no PLT or GOT in the picture at all. One parameter in each case. */
BC_KEEP unsigned long bc_pointer_walk(const char *s)
{
    unsigned long len = 0;
    while (s[len] != '\0')
        len++;
    return len;
}

/* 4. A value merged from two predecessors and then used, which at -O2 and -Os
 * becomes a conditional move on most targets and a branch on some. Whatever
 * name the recovery gives the merged value must be assigned on both arms in
 * every configuration. */
BC_KEEP long bc_select_join(long a, long b, long c)
{
    long picked = c;
    if (a > b)
        picked = a;
    return picked + (a > b ? b : c);
}

/* 5. The smallest possible leaf: two arguments, no frame, no calls. It exists
 * so that `discovery invariance` has a function with no unwind-relevant
 * structure at all — at -O2 with `-fno-asynchronous-unwind-tables` this
 * compiles to a handful of instructions with no FDE, no frame pointer and no
 * canary, which is the hardest shape for an `.eh_frame`-driven function
 * discovery to see. */
BC_KEEP int bc_leaf_add(int a, int b)
{
    return a + b;
}

/* Address-taken through `volatile`, which is what pins the interfaces above:
 * the address escapes, so no interprocedural pass may rewrite a signature, and
 * the calls below keep every function reachable in a whole-program (-flto)
 * link of an executable. */
static long (*volatile bc_p_many)(long, long, long, long, long, long, long, long) =
    bc_many_parameters;
static long (*volatile bc_p_buffer)(const unsigned char *, unsigned long) =
    bc_buffer_and_scalars;
static unsigned long (*volatile bc_p_walk)(const char *) = bc_pointer_walk;
static long (*volatile bc_p_select)(long, long, long) = bc_select_join;
static int (*volatile bc_p_leaf)(int, int) = bc_leaf_add;

int main(void)
{
    static const unsigned char data[16] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    };

    bc_sink += bc_p_many(1, 2, 3, 4, 5, 6, 7, 8);
    bc_sink += bc_p_buffer(data, sizeof data);
    bc_sink += (long)bc_p_walk("configuration");
    bc_sink += bc_p_select(3, 2, 1);
    bc_sink += bc_p_leaf(2, 3);
    return (int)(bc_sink & 1);
}
