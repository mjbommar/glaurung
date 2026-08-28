#include <stdint.h>

/* Three frame slots with different fates, so a local-rename test can tell
 * "declined" from "corrupted" from "applied".
 *
 * `total` survives every pass and is declared in the output. `limit` is copy-
 * propagated away at -O0 by the time the body is rendered, so it has a frame
 * slot the analyst can name but no variable in the emitted C. `i` is the loop
 * induction variable, whose frame coordinate the promotion pass may withhold
 * as ambiguous.
 *
 * WHY THE SHAPE MATTERS. Naming a local also protects it from elimination, and
 * a name applied without a recovered type loses the slot's width along with its
 * `local_` identity -- which the renderer then reads as an address. Measured on
 * a stripped -O0 build of this file, renaming the surviving slot with no type
 * attached turned
 *
 *     int local_c;  local_c = 0;  ...  return (unsigned int)(local_c);
 *
 * into
 *
 *     long running_total;  *(int *)(running_total) = 0;
 *
 * a pointer store synthesised from a scalar assignment. So a rename is applied
 * only alongside a type, and this fixture is what pins that.
 *
 * Built STRIPPED by the test: with DWARF the locals already carry their source
 * names and the analyst overlay has nothing to do.
 */

__attribute__((noinline)) int scan(const uint8_t *p, int n) {
    int total = 0;
    int limit = n;
    if (!p || n < 0) {
        return -1;
    }
    for (int i = 0; i < limit; i++) {
        total += p[i];
    }
    return total;
}
