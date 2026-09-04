/* Decompiler-dialect fixture -- binja.
 *
 * PROVENANCE: captured output, not a reconstruction. Copied verbatim from
 * DecBench's published sample set (MIT licensed), which stores one decompiled
 * body per (project, binary, function, backend):
 *
 *   $DECBENCH_DIR/site/data/samples.json  ->  [i]["decompiled"]["binja"]
 *
 * Backend version from that run's decompiler_versions map: Binary Ninja 5.3.9757.
 * No JVM, no Joern and no DecBench pipeline is needed to read the file; it is
 * a JSON blob on disk. Nothing below was edited.
 *
 * Read with docs/design/source-front-ends/decompiler-dialects.md.
 */

/* case: history_def_last
 * provenance: captured
 * source: libedit / libedit.so.0.0
 * expect: history_def_last
 * note: Binary Ninja's ordinary style: int64_t/int128_t sized types, arg1/arg2
 * note: parameter names, register-named locals, pointer arithmetic on void*.
 */
  int64_t history_def_last(void* arg1, int128_t* arg2)

{
    int128_t* rax = *(arg1 + 0x20);
    *(arg1 + 0x28) = rax;
    
    if (rax != arg1)
    {
        *arg2 = *rax;
        return 0;
    }
    
    *arg2 = 4;
    *(arg2 + 8) = "last event not found";
    return 0xffffffff;
}


/* case: usage
 * provenance: captured
 * source: shadow / newgidmap
 * expect: -
 * gap: trailing function attribute after the parameter list (__noreturn)
 * note: 'void usage() __noreturn' is not C in any dialect: __noreturn is an
 * note: identifier where C expects '{', ';' or a K&R declaration list.
 * note: DecBench's sanitize_decompiled_c does NOT rewrite it -- Joern's CDT
 * note: parser tolerates it on its own. This is the single largest measured
 * note: gap between Joern-plus-sanitizer and our front end on binja text.
 */
  void usage() __noreturn

{
    __fprintf_chk(stderr, 1, 
        dcgettext(nullptr, 
            "usage: %s <pid> <gid> <lowergid> <count> [ <gid> <lowergid> <count> ] ... \n", 5), 
        data_40eeb0);
    exit(1);
    /* no return */
}


/* case: bi_reverse
 * provenance: captured
 * source: gzip / gzip
 * expect: -
 * gap: trailing function attribute after the parameter list (__pure)
 * note: Same shape as __noreturn, different attribute. Binary Ninja emits
 * note: __noreturn, __pure and __const this way.
 */
  uint64_t bi_reverse(uint32_t arg1, int32_t arg2) __pure

{
    uint32_t var_14 = arg1;
    int32_t i = arg2;
    int32_t rbx = 0;
    
    do
    {
        int32_t rbx_1 = rbx | (var_14 & 1);
        var_14 u>>= 1;
        rbx = rbx_1 * 2;
        i -= 1;
    } while (i > 0);
    
    return rbx >> 1;
}


/* case: handler
 * provenance: captured
 * source: sysvinit / wall
 * expect: -
 * gap: trailing function attribute after the parameter list (__noreturn)
 * note: The smallest instance: a single call and a '/* no return */' comment.
 */
  void handler() __noreturn

{
    __longjmp_chk(&data_4060e0, 1);
    /* no return */
}
