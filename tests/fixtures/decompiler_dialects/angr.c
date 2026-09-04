/* Decompiler-dialect fixture -- angr.
 *
 * PROVENANCE: captured output, not a reconstruction. Copied verbatim from
 * DecBench's published sample set (MIT licensed), which stores one decompiled
 * body per (project, binary, function, backend):
 *
 *   $DECBENCH_DIR/site/data/samples.json  ->  [i]["decompiled"]["angr"]
 *
 * Backend version from that run's decompiler_versions map: angr 9.2.223.
 * No JVM, no Joern and no DecBench pipeline is needed to read the file; it is
 * a JSON blob on disk. Nothing below was edited.
 *
 * Read with docs/design/source-front-ends/decompiler-dialects.md.
 */

/* case: bi_reverse
 * provenance: captured
 * source: gzip / gzip
 * expect: bi_reverse
 * note: angr's style: a0/a1 parameters, vN locals with a '// reg' comment,
 * note: do/while loops. Plain C throughout.
 */
unsigned int bi_reverse(unsigned int a0, int a1)
{
    unsigned int v4;  // ebx
    unsigned int v5;  // ebx
    unsigned int v6;  // ebx
    int i;  // [bp-0x18]
    unsigned int v1;  // [bp-0x14]
    unsigned int v2;  // [bp-0x14]

    v1 = a0;
    i = a1;
    v4 = 0;
    do
    {
        v2 = v1;
        v1 = v2 >> 1;
        v6 = (v4 | v2 & 1) * 2;
        i -= 1;
        v4 = v6;
    } while (i > 0);
    return (v5 | v2 & 1) & 2147483647;
}


/* case: usage
 * provenance: captured
 * source: shadow / newgidmap
 * expect: usage
 * note: A file-scope 'extern unsigned long long stderr;' redeclaration and an
 * note: 'exit(1); /* do not return */' tail. Both parse.
 */
extern unsigned long long stderr;

void usage(void)
{
    unsigned long long v2;  // r12
    char *v3;  // rax
    unsigned long long v0;  // [bp-0x8]

    v0 = v2;
    v3 = dcgettext(NULL, "usage: %s <pid> <gid> <lowergid> <count> [ <gid> <lowergid> <count> ] ... \n", 5);
    __fprintf_chk(stderr, 0x1, v3);
    exit(1); /* do not return */
}


/* case: history_def_last
 * provenance: captured
 * source: libedit / libedit.so.0.0
 * expect: history_def_last
 * note: angr emits struct typedefs ahead of the function and uses uint128_t.
 * note: The whole translation unit, typedefs included, is ordinary C.
 */
typedef struct struct_0 {
    char padding_0[32];
    struct struct_1 *field_20;
    struct struct_0 *field_28;
} struct_0;

typedef struct struct_1 {
    uint128_t field_0;
} struct_1;

double history_def_last(void* idx, void* a1)
{
    uint128_t *v1;  // rax
    uint128_t v2;  // xmm0
    unsigned long v3;  // xmm0lq

    v1 = &idx->field_20->field_0;
    idx->field_28 = v1;
    if (v1 == idx)
    {
        *((unsigned int *)a1) = 4;
        *((char **)&a1[8]) = "last event not found";
        return v3;
    }
    v2 = *(v1);
    *((uint128_t *)a1) = v2;
    return (unsigned long long)v2;
}
