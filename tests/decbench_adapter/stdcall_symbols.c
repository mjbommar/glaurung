/* i386 PE stdcall decoration fixture for the DecBench symbol resolver.
 *
 * Built by tests/decbench_adapter/build.sh with i686-w64-mingw32-gcc. Every
 * symbol exists to pin one clause of the resolver contract in
 * tools/decbench_symbols.py; MANIFEST.json records which.
 *
 * The hand-written symbols use COFF `.def/.scl/.type/.endef` so they are typed
 * as FUNCTIONS. A bare `.globl` label is emitted with no type and the object
 * reader reports it as `data` -- which would make the collision controls test
 * the data-refusal clause instead of the clause they are here for.
 */
#include <windows.h>

/* --- F1a: stdcall, so the symbol table holds `_name@N`. `N` is the
 * callee-popped argument byte count, so it differs per function and cannot be
 * guessed from the name. --- */
__attribute__((stdcall)) int worker_fn(int a) { return a * 3 + 1; }
__attribute__((stdcall)) int entry_fn(int a, int b, int c) { return a + b * c; }
__attribute__((stdcall)) int handler_fn(int a, int b, int c, int d) {
  return a - b + c * d;
}

/* --- Collision control: two DISTINCT functions, one literally `worker` and
 * one literally `_worker`. A request for "worker" must take the exact match
 * (clause 1), not the underscore fallback (clause 2). --- */
__asm__(".globl worker\n"
        ".def worker; .scl 2; .type 32; .endef\n"
        "worker:\n  movl $11, %eax\n  ret\n");
__asm__(".globl _worker\n"
        ".def _worker; .scl 2; .type 32; .endef\n"
        "_worker:\n  movl $22, %eax\n  ret\n");

/* --- Ambiguity control (clause 4): two stdcall symbols with the SAME base
 * name and different byte counts, at distinct addresses. Both canonicalize to
 * "dup". This is a within-tier collision, which precedence cannot resolve --
 * unlike `_dup` vs `_dup@8`, where clause 2 simply outranks clause 3. --- */
__asm__(".globl _dup@8\n"
        ".def _dup@8; .scl 2; .type 32; .endef\n"
        "_dup@8:\n  movl $33, %eax\n  ret\n");
__asm__(".globl _dup@12\n"
        ".def _dup@12; .scl 2; .type 32; .endef\n"
        "_dup@12:\n  movl $44, %eax\n  ret\n");

/* --- A DATA symbol named like a function (clause 5). A local-body request for
 * "lookalike" must be refused, not answered with this address. --- */
__attribute__((used)) int _lookalike = 0x5eed;

/* --- Plain cdecl: the `_name` fallback (clause 2) must keep working. --- */
int crc32_fn(int x) { return x ^ 0x04c11db7; }

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID v) {
  (void)h; (void)r; (void)v;
  return TRUE;
}
