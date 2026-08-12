/* Shapes that make a decompiler's *frame and signature model* observable.
 *
 * These are not chosen to resemble any particular benchmark. They are the
 * minimal source shapes for which a recovered function can be internally
 * self-contradictory — where the emitted C can claim a frame layout or a
 * signature that could not have produced the machine code it came from.
 *
 * Each property below is checkable without a reference decompiler, and most are
 * checkable without ground truth at all, because they are consistency
 * properties of the emitted translation unit itself.
 */

#include <stddef.h>

/* 1. A large buffer sitting immediately below smaller scalars.
 *
 * The recovered frame must place `scratch` and the three scalars in DISJOINT
 * byte ranges. A decompiler that recovers the buffer's start correctly but its
 * length from some unrelated bound will emit an array that swallows its
 * neighbours; recompiled, the compiler then allocates them separately, the
 * frame grows, and every stack offset shifts. */
long buffer_adjacent_scalars(const unsigned char *in, unsigned long n)
{
    unsigned char scratch[96];
    long first = 0, second = 0, third = 0;
    unsigned long i;

    for (i = 0; i < n && i < sizeof scratch; i++) {
        scratch[i] = in[i];
        first += scratch[i];
    }
    second = first * 3;
    third = second - (long)i;
    return first + second + third;
}

/* 2. More parameters than any of the four targets passes in registers, so the
 * tail of the list necessarily arrives on the stack. The recovered arity is
 * then a claim about the ABI that can be checked against the source. */
long many_parameters(long a, long b, long c, long d,
                     long e, long f, long g, long h)
{
    return a + (b * 2) + (c * 3) + (d * 4) + (e * 5) + (f * 6) + (g * 7) + (h * 8);
}

/* 3. A pointer selected in two predecessors and consumed at the join.
 *
 * This is the shape behind a whole family of defects: the value is live across
 * a control-flow merge, so a decompiler that merges the two definitions into a
 * single name loses which one reaches the use. Whatever it emits must still
 * name a value that is assigned on every path to the use. */
unsigned long join_selected_length(int which, const char *left, const char *right)
{
    const char *chosen;
    unsigned long len = 0;

    if (which > 0)
        chosen = left;
    else
        chosen = right;

    while (chosen[len] != '\0')
        len++;
    return len;
}

/* 4. Two buffers of different sizes plus a scalar between them, so an
 * off-by-one in either extent is observable as an overlap rather than only as
 * a wrong number. */
long two_buffers_and_a_scalar(const unsigned char *in, unsigned long n)
{
    unsigned char head[32];
    long middle = 0;
    unsigned char tail[64];
    unsigned long i;

    for (i = 0; i < 32 && i < n; i++)
        head[i] = in[i];
    middle = (long)i;
    for (i = 0; i < 64 && i < n; i++)
        tail[i] = in[i];

    return (long)head[0] + middle + (long)tail[0];
}

/* 5. A local whose only definition is inside a loop that may not execute.
 *
 * The recovered C must not read it before some assignment dominates the read;
 * if the decompiler drops the initialising store it produces a function whose
 * result is unspecified, which no execution differential on a fixed input
 * necessarily catches. */
long conditionally_initialised(const long *values, unsigned long n)
{
    long acc = 0;
    unsigned long i;

    for (i = 0; i < n; i++)
        acc += values[i];
    return acc;
}

/* ---------------------------------------------------------------------------
 * Shapes 6-11 exist because the properties above were only ever compiled from
 * shapes 1-5, and the defect they were written to catch appeared in a different
 * fixture and went unseen for four commits.
 *
 * These are chosen for what the COMPILER emits, not for what the source says.
 * Each one is a source shape whose optimised form is an instruction or idiom
 * that *defines its destination conditionally, or not at all* on some input —
 * the machine-level shape behind an unassigned read. A decompiler that models
 * such an instruction by preserving the destination's prior value creates a
 * read-before-write, and a read-before-write of a physical register sitting in
 * an argument slot is promoted to a parameter. So the same root cause surfaces
 * as three different symptoms: an unassigned local, a phantom parameter, and an
 * arity that contradicts the source.
 * ------------------------------------------------------------------------- */

/* 6. A shift-until-zero loop, which every optimiser turns into a bit-scan.
 *
 * `bsr`/`bsf` (x86) and `clz` (ARM) DEFINE their destination only when the
 * source is non-zero; Intel documents it as undefined otherwise, and AMD
 * preserves it. A lowering that models "preserved" reads the destination first,
 * and the emitted C then either declares a local it never assigns or grows
 * parameters that do not exist. One parameter in, one parameter out. */
int shift_until_zero_shape(unsigned x)
{
    int n = 0;
    while (x) { x >>= 1; n++; }
    return n;
}

/* 7. The mirror of 6, counting from the bottom — the forward-scan encoding. */
int trailing_zero_shape(unsigned x)
{
    int n = 0;
    if (x == 0)
        return 32;
    while ((x & 1u) == 0) { x >>= 1; n++; }
    return n;
}

/* 8. Signed division by a power of two, which compiles to the bias-and-shift
 * rounding idiom `(v < 0 ? v + (2^k - 1) : v) >> k`.
 *
 * That is a conditional expression whose arms are BOTH live and both defined.
 * A pass that collapses a conditional on the belief that one arm is undefined
 * silently changes the result for every non-negative input — which is exactly
 * how the x86-64 control lane was lost. The differential catches it only
 * because a non-negative value is exercised, so keep both signs in play. */
long signed_halving(long v, long w)
{
    return (v / 4) + (w / 8) + ((-v) / 2);
}

/* 9. Signed remainder by a power of two — the same bias with the mask kept. */
long signed_remainder(long v)
{
    return (v % 8) + ((-v) % 16);
}

/* 10. A guard the optimiser fuses into branchless bitwise arithmetic.
 *
 * At -O2 this becomes a single expression of the form `(a | b) == 0` over two
 * comparisons, with no branch between them. Whatever the decompiler emits for
 * it must still be a condition every operand of which is assigned. */
long fused_guard(long a, long b)
{
    if (a == 1 || a < 1)
        return b * 2;
    if (a > 3 && b > 3)
        return a + b;
    return a - b;
}

/* 11. A select whose two arms come from different predecessors, which becomes
 * a conditional move rather than a branch. `cmov` writes its destination only
 * when the condition holds, so it carries the same preserved-destination trap
 * as 6, in the one place where the preserved value is genuinely live. */
long conditional_move_shape(long a, long b, long c)
{
    long picked = c;
    if (a > b)
        picked = a;
    return picked + (a > b ? b : c);
}
