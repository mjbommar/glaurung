/* Decompiler-dialect fixture -- ida.
 *
 * PROVENANCE: captured output, not a reconstruction. Copied verbatim from
 * DecBench's published sample set (MIT licensed), which stores one decompiled
 * body per (project, binary, function, backend):
 *
 *   $DECBENCH_DIR/site/data/samples.json  ->  [i]["decompiled"]["ida"]
 *
 * Backend version from that run's decompiler_versions map: IDA Pro 9.20 (Hex-Rays).
 * Reading it needs no JVM, no Joern and no DecBench pipeline -- it is a JSON
 * blob on disk. Nothing below was edited.
 *
 * Read with docs/design/source-front-ends/decompiler-dialects.md.
 *
 * IMPORTANT -- what DecBench's 'ida' column actually contains. IDA is the
 * ONLY backend DecBench normalizes before storing:
 * decbench/decompilers/raw/ida_raw.py::_CODE_REPLACEMENTS rewrites
 * __int64 -> long long, _QWORD -> long long, _BYTE -> char (and friends)
 * and DELETES the substrings '__cdecl ', '__fastcall ', '__stdcall ',
 * '__thiscall ', '__usercall ' and '__noreturn '. So the captured cases
 * below are already ordinary C, and DecBench's ida GED numbers say nothing
 * about whether Joern parses genuine Hex-Rays text. The two reconstruction
 * cases at the end cover the dialect as Hex-Rays actually prints it.
 */

/* case: bi_reverse
 * provenance: captured
 * source: gzip / gzip
 * expect: bi_reverse
 * note: Post-normalization: 'long long', not '__int64'.
 */
long long bi_reverse(unsigned int a1, int a2)
{
  unsigned int v2; // ebx
  int v3; // eax

  v2 = 0;
  do
  {
    v3 = a1 & 1;
    a1 >>= 1;
    v2 = 2 * (v3 | v2);
    --a2;
  }
  while ( a2 > 0 );
  return v2 >> 1;
}


/* case: history_def_last
 * provenance: captured
 * source: libedit / libedit.so.0.0
 * expect: history_def_last
 * note: __m128i and _mm_loadu_si128 survive normalization and parse fine.
 */
long long history_def_last(long long a1, long long a2)
{
  const __m128i *v2; // rax
  __m128i v3; // xmm0

  v2 = *(const __m128i **)(a1 + 32);
  *(long long *)(a1 + 40) = v2;
  if ( v2 == (const __m128i *)a1 )
  {
    *(int *)a2 = 4;
    *(long long *)(a2 + 8) = "last event not found";
    return 0xFFFFFFFFLL;
  }
  else
  {
    v3 = _mm_loadu_si128(v2);
    *(__m128i *)a2 = v3;
    return 0;
  }
}


/* case: dis_func1
 * provenance: captured
 * source: chibios / ch
 * expect: -
 * gap: __spoils<R1,R2,R3,R12,LR> declaration specifier
 * note: The single ida cell of 500 in the sample set that we do not recover.
 * note: __spoils is not in ida_raw.py's replacement table, so it is the one
 * note: IDA-ism that actually reaches Joern -- which parses it and we do not.
 */
void __spoils<R1,R2,R3,R12,LR> dis_func1(char a1)
{
  sub_8006EC8(a1);
}


/* case: raw_hexrays_fastcall
 * provenance: RECONSTRUCTION
 * source: hand-written in the Hex-Rays house style; no IDA install on this machine
 * expect: raw_hexrays_fastcall
 * note: What Hex-Rays prints BEFORE DecBench's normalization: __int64 return,
 * note: __fastcall, _QWORD/_BYTE pseudo-types, a1/a2 parameter names, LODWORD.
 * note: This is a reconstruction, NOT captured output.
 */
__int64 __fastcall raw_hexrays_fastcall(_QWORD *a1, unsigned __int8 a2)
{
  _BYTE *v3; // rax

  v3 = (_BYTE *)a1[1];
  if ( !v3 )
    return 0LL;
  *v3 = a2;
  return LODWORD(a1[0]);
}


/* case: raw_hexrays_usercall
 * provenance: RECONSTRUCTION
 * source: hand-written in the Hex-Rays house style; no IDA install on this machine
 * expect: raw_hexrays_usercall
 * note: __usercall with explicit register slots on the function and on each
 * note: parameter. DecBench's ida_raw.py deletes the string '__usercall ' but
 * note: leaves '@<eax>' in place, and sanitize_decompiled_c's _REG_ANNOTATION
 * note: regex (\s*@\s*[a-z]\w+\b) does not match '@<eax>' because of the
 * note: '<'. Neither DecBench layer removes it.
 * note: This is a reconstruction, NOT captured output.
 */
int __usercall raw_hexrays_usercall@<eax>(int a1@<ecx>, int a2@<edx>)
{
  if ( a1 > a2 )
    return a1;
  return a2;
}
