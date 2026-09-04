/* Decompiler-dialect fixture -- r2dec.
 *
 * PROVENANCE: captured output, not a reconstruction. Copied verbatim from
 * DecBench's published sample set (MIT licensed), which stores one decompiled
 * body per (project, binary, function, backend):
 *
 *   $DECBENCH_DIR/site/data/samples.json  ->  [i]["decompiled"]["r2dec"]
 *
 * Backend version from that run's decompiler_versions map: r2dec on radare2 6.0.8.
 * Reading it needs no JVM, no Joern and no DecBench pipeline -- it is a JSON
 * blob on disk. Nothing below was edited.
 *
 * Read with docs/design/source-front-ends/decompiler-dialects.md.
 */

/* case: bi_reverse
 * provenance: captured
 * source: gzip / gzip
 * expect: bi_reverse
 * note: r2dec emits register names as if they were variables (eax, rbp) and
 * note: '*((rbp - 0xc))' memory expressions. Not compilable C, but it is
 * note: syntactically C, and both Joern and we parse it.
 */
/* r2dec pseudo code output (r2 6.0.8) */
/* /in/gzip @ 0x3bed */
#include <stdint.h>
 
int32_t bi_reverse (signed int64_t arg1, uint32_t arg2) {
    uint32_t var_10h;
    signed int64_t var_ch;
    int64_t var_8h;
    rdi = arg1;
    rsi = arg2;
    *((rbp - 0xc)) = edi;
    *((rbp - 0x10)) = esi;
    ebx = 0;
    do {
        eax = *((rbp - 0xc));
        eax &= 1;
        ebx |= eax;
        *((rbp - 0xc)) >>= 1;
        ebx += ebx;
        *((rbp - 0x10))--;
    } while (*((rbp - 0x10)) > 0);
    eax = ebx;
    eax >>= 1;
    rbx = *((rbp - 8));
    return eax;
}


/* case: usage
 * provenance: captured
 * source: shadow / newgidmap
 * expect: usage
 * note: A leading '#include <stdint.h>' that no preprocessor will run here,
 * note: and 'obj.stderr' -- a dotted r2 flag name used inside an expression.
 */
/* r2dec pseudo code output (r2 6.0.8) */
/* /in/newgidmap @ 0x4140 */
#include <stdint.h>
 
uint64_t usage (void) {
    edx = 5;
    r12 = *(0x0000eeb0);
    rax = dcgettext (0, "usage: %s <pid> <gid> <lowergid> <count> [ <gid> <lowergid> <count> ] ... \n");
    rdi = *(obj.stderr);
    rcx = r12;
    esi = 1;
    rdx = rax;
    eax = 0;
    fprintf_chk ();
    return exit (1);
}


/* case: sendAmperage
 * provenance: captured
 * source: cleanflight / cleanflight_DALRCF405
 * expect: -
 * gap: the cell is not C at all -- it is r2dec's crash message
 * note: 6 of the 423 r2dec cells in the sample set are prose like this.
 * note: Nothing can recover a CFG from them and Joern abstains too. Recorded
 * note: so the recovery denominator stays honest instead of quietly shrinking.
 */
r2dec has crashed (info: /in/cleanflight_DALRCF405.elf @ 0x8033cb0).
Please report the bug at https://github.com/wargio/r2dec-js/issues
Enable -e r2dec.debug=true to check the javascript backtrace.
Use the command 'pddi' to generate the needed data for the issue.
