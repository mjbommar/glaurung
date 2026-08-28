#include <stdint.h>

/* Two functions where the caller reaches the callee through a PLT stub, which
 * is what an intra-module call in a shared object always compiles to.
 *
 * WHY THE PLT MATTERS HERE. An analyst rename is recorded against the
 * function's own entry VA. The call does not target that VA -- it targets the
 * stub, at a different address, which the address map names `validate@plt`.
 * An overlay that rewrites only the renamed address therefore renames the
 * function header and leaves every call site reading the old name, which is
 * the split-brain output the whole feature exists to avoid.
 *
 * WHY THE ARGUMENTS MATTER. The recovered symbol environment is keyed by the
 * identifier the renderer prints, so a rename that is applied BEFORE callee
 * analysis makes that analysis look up a name no symbol source knows. It finds
 * nothing and silently downgrades `int validate(char *, int)` to `long
 * f(void)` -- the call site keeps the new name and loses its arguments. The
 * two-argument signature and the second call with a *different* second
 * argument are what make that downgrade visible.
 */

__attribute__((noinline)) int validate(const uint8_t *p, int n) {
    if (!p || n < 4) {
        return -1;
    }
    return p[0] + p[1] * 2 + n;
}

__attribute__((noinline)) int driver(const uint8_t *p, int n) {
    int a = validate(p, n);
    if (a < 0) {
        return a;
    }
    return a + validate(p, n - 1);
}
