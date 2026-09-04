/* Decompiler-dialect fixture -- RetDec.
 *
 * PROVENANCE: RECONSTRUCTION. Every case in this file is hand-written in
 * RetDec's documented house style. It is NOT captured output:
 *
 *   - RetDec is not installed on this machine (no retdec-decompiler on PATH).
 *   - DecBench registers a retdec backend
 *     (decbench/decompilers/dockerized.py::RetDecDecompiler, Docker image,
 *     `retdec-decompiler <binary> -o out.c`) but the published run we have on
 *     disk contains NO retdec column: samples.json's decompiled maps and
 *     published_function_results.json's decompilers list both omit it.
 *
 * So unlike every other file in this directory, nothing here is evidence about
 * what RetDec really prints. It is a placeholder that makes the shapes RetDec
 * is documented to emit testable, and it must be replaced with captured output
 * before any claim is made about RetDec specifically.
 *
 * Note that RetDec is the one DecBench backend whose adapter does NOT
 * normalize: DockerizedDecompiler._normalize_code is the identity, so whatever
 * RetDec prints is what Joern would have to parse (after the shared
 * sanitize_decompiled_c pass).
 *
 * Read with docs/design/source-front-ends/decompiler-dialects.md.
 */

/* case: function_401000
 * provenance: RECONSTRUCTION
 * source: hand-written; RetDec not installed
 * expect: function_401000
 * note: RetDec's ordinary style: an '// Address range' banner comment,
 * note: int32_t/int64_t sized types, function_<addr> names, vN locals.
 */
// Address range: 0x401000 - 0x401046
int32_t function_401000(int32_t a1, int32_t a2) {
    int32_t v1 = a1;
    int32_t v2 = 0;
    while (v1 > 0) {
        v2 += v1 & a2;
        v1 >>= 1;
    }
    return v2;
}


/* case: function_401050
 * provenance: RECONSTRUCTION
 * source: hand-written; RetDec not installed
 * expect: function_401050
 * note: RetDec's __asm_/__pseudo_ intrinsics for instructions it cannot lift.
 * note: They are ordinary call expressions and parse as such.
 */
// Address range: 0x401050 - 0x401072
int64_t function_401050(int64_t a1) {
    __asm_cpuid(0);
    if (__pseudo_cond_branch(a1)) {
        return 0;
    }
    return a1;
}
