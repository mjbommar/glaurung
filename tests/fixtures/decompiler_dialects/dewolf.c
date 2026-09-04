/* Decompiler-dialect fixture -- dewolf.
 *
 * PROVENANCE: captured output, not a reconstruction. Copied verbatim from
 * DecBench's published sample set (MIT licensed), which stores one decompiled
 * body per (project, binary, function, backend):
 *
 *   $DECBENCH_DIR/site/data/samples.json  ->  [i]["decompiled"]["dewolf"]
 *
 * Backend version from that run's decompiler_versions map: dewolf v2026.7.11.
 * No JVM, no Joern and no DecBench pipeline is needed to read the file; it is
 * a JSON blob on disk. Nothing below was edited.
 *
 * Read with docs/design/source-front-ends/decompiler-dialects.md.
 */

/* case: history_def_last
 * provenance: captured
 * source: libedit / libedit.so.0.0
 * expect: -
 * gap: doubled return type and doubled parameter list in the definition
 * note: 'long int64_t f(void* arg1, int128_t* arg2)(void * arg1, int128_t * arg2)'
 * note: -- dewolf prints its Binary Ninja signature and then a C signature, so
 * note: the declarator has two parameter lists. This is the dominant dewolf
 * note: shape: 201 of the 295 dewolf cells we lose look like this, and Joern
 * note: loses 185 of those 201 too.
 */
long int64_t history_def_last(void* arg1, int128_t* arg2)(void * arg1, int128_t * arg2){void * var_0;
int128_t * var_2;var_0 = arg1 + 32L;
var_2 = *var_0;
*(arg1 + 40L) = *var_0;if (var_2 != arg1) {*arg2 = *var_2;
return 0L;}*arg2 = 0x4;
*(arg2 + 8L) = "last event not found";
return 0xffffffff;}


/* case: usage
 * provenance: captured
 * source: shadow / newgidmap
 * expect: -
 * gap: doubled return type plus a trailing __noreturn taking a parameter list
 * note: 'void void usage() __noreturn(){...}'. 'void void' alone parses; the
 * note: '__noreturn()' between the parameter list and the body does not.
 * note: Joern recovers this one, so it is a real Joern-versus-us gap.
 */
extern long data_40eeb0 = 0L;
extern unsigned long * stderr = 0UL;



void void usage() __noreturn(){long var_5;
unsigned long * var_3;
char * var_4;var_5 = data_40eeb0;
var_4 = dcgettext(/* domainname */ 0UL, /* msgid */ "usage: %s <pid> <gid> <lowergid> <count> [ <gid> <lowergid> <count> ] ... \\n", /* category */ 5);
var_3 = stderr;
__fprintf_chk(/* fp */ var_3, /* flag */ 1, /* format */ var_4, var_5);
exit(/* status */ 1);}


/* case: bi_reverse
 * provenance: captured
 * source: gzip / gzip
 * expect: -
 * gap: doubled return type plus a trailing __pure with a parameter list
 * note: Same shape as usage but with __pure. Joern loses this one as well.
 */
unsigned long uint64_t bi_reverse(uint32_t arg1, int32_t arg2) __pure(unsigned int arg1, int arg2){unsigned int var_1;
int var_0;var_0 = arg2;
arg2 = 0;while (true){var_1 = arg1 >> 1;
arg2 |= arg1 & 1;
arg2 += arg2;
var_0--;if (var_0 <= 0) {break;}arg1 = var_1;}return arg2 >> 1;}
