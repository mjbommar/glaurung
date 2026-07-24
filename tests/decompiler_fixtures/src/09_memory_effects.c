/* 09_memory_effects.c
 *
 * Memory-effects fixture. Every function that touches memory does so through
 * caller-supplied int* buffers (or an observable volatile counter read back via
 * a getter), so an execution-differential test (original vs. recompiled
 * decompilation) catches a DROPPED store, a reordered load, an unsafe
 * dead-store elimination, or a vectorizer intrinsic lowering that silently loses
 * an effect. Each observable path yields a UNIQUE value.
 *
 * Targets review #2c (dropped intrinsic effects / unsafe DSE / vectorizable
 * loops). Differential-testable functions are pure over their int* / int args:
 * given an 8-int input buffer they mutate it deterministically and/or return an
 * int, so the gate can diff both the return value and the buffer contents.
 *
 * Differential vs. structural:
 *   - cas_update(), mem_copy(), mem_set(), vec_sum(), vec_transform(): DIFFERENTIAL.
 *     Pure over their int* / int arguments; drive with an 8-int buffer.
 *   - tick()/tick_n()/read_counter(): the volatile global is a STRUCTURAL target
 *     (true MMIO-style volatile semantics / C11-atomic ordering are structural
 *     assertions), but the effect is made observable — and thus differential —
 *     by driving a call SEQUENCE and reading the count back through read_counter().
 *
 * No libc: memcpy/memset are written as explicit inline loops; the "atomic"
 * compare-and-swap is plain C. No floats anywhere.
 */
#include <stdint.h>

/* --- volatile MMIO-style counter --------------------------------------- */

/* A volatile global that must be reloaded/restored on every access. A correct
 * lowering keeps every read and write; an over-eager optimizer that caches or
 * DSE-drops a write diverges the sequence observed through read_counter(). */
static volatile int g_counter = 0;

/* Single observable increment (MMIO-style write). */
void tick(void) {
    g_counter = g_counter + 1;
}

/* n observable increments via an explicit loop — each iteration is a real
 * volatile load+store that must not be coalesced away. */
void tick_n(int n) {
    for (int i = 0; i < n; i++)
        g_counter = g_counter + 1;
}

/* Getter that makes the counter observable, so a driven call sequence becomes
 * differential-testable through this return value. */
int read_counter(void) {
    return g_counter;
}

/* Reset so a differential harness can start each sequence from a known state. */
void reset_counter(void) {
    g_counter = 0;
}

/* --- compare-and-swap, written in plain C (no libc atomics) ------------- */

/* CAS-like update over an int*. Returns 1 and stores `newv` iff *p == oldv,
 * else returns 0 and leaves *p unchanged. Both the return value and the buffer
 * mutation are observable, so a dropped store shows up in the differential. */
int cas_update(int *p, int oldv, int newv) {
    if (*p == oldv) {
        *p = newv;
        return 1;
    }
    return 0;
}

/* --- memcpy / memset as explicit inline loops over int* buffers --------- */

/* Copy `n` ints from src to dst. Written as a loop so a decompiler that
 * recognizes and re-emits a memcpy intrinsic must preserve every element store. */
void mem_copy(int *dst, const int *src, int n) {
    for (int i = 0; i < n; i++)
        dst[i] = src[i];
}

/* Fill `n` ints of dst with `val`. Explicit loop form of memset. */
void mem_set(int *dst, int val, int n) {
    for (int i = 0; i < n; i++)
        dst[i] = val;
}

/* --- vectorizable stack-buffer loops (catch SSE/NEON lowering) ---------- */

/* Sum of `n` ints. At -O2/-O3 this is a prime SSE/NEON reduction candidate; a
 * vectorized lowering that drops a tail element or mishandles the reduction
 * diverges the returned total. Deterministic and pure over (a, n). */
int vec_sum(const int *a, int n) {
    int s = 0;
    for (int i = 0; i < n; i++)
        s += a[i];
    return s;                       /* unique per input buffer */
}

/* In-place transform buf[i] = buf[i]*3 + 7 over `n` ints — an elementwise map a
 * compiler may vectorize. Both the mutated buffer and (as a checksum) the return
 * are observable, so a dropped or reordered store is caught differentially. */
int vec_transform(int *buf, int n) {
    int check = 0;
    for (int i = 0; i < n; i++) {
        buf[i] = buf[i] * 3 + 7;
        check ^= buf[i];
    }
    return check;
}
