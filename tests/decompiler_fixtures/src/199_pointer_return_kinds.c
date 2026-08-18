#include <stdint.h>

/* FUNCTIONS THAT RETURN A POINTER.
 *
 * The census that produced this fixture found exactly ONE pointer return in the
 * 900 function definitions of this corpus: `192_pointer_chased_list`'s
 * `l192_find_key`, which returns `struct L192Node *` after chasing a `next`
 * link. Every other function in every language returns an integer, a float, a
 * `void`, or (in 195/197/198) an aggregate.
 *
 * That one function fixes a single point in a space with several independent
 * axes, and it is the axis of "an address recovered from a LOAD". The three
 * this file adds:
 *
 *   * `void *` — the pointee carries no width. `describe_pointer` in
 *     `src/debug/dwarf_signatures.rs` gives it a synthetic `u8` pointee, so the
 *     recovered C, the ctypes prototype and the returned address all have to
 *     agree about an element size that the source never wrote down. Nothing in
 *     the corpus returns one.
 *   * `const T *` — the same address with `konst: true` in the descriptor. A
 *     recovery that drops the qualifier still compiles; one that drops it and
 *     then WRITES through the result does not. Nothing in the corpus returns
 *     one.
 *   * an address formed by pure ARITHMETIC (`buf + k`) rather than found by a
 *     scan. `l192_find_key` returns a value it loaded; a computed address is
 *     the case where "pointer" and "integer offset" are hardest to tell apart,
 *     and where a recovery that silently converts one into the other is still
 *     type-correct C.
 *
 * All of these are execution-differential ONLY through the manifest's
 * `pointer_return_arg`: `exec_class` refuses a pointer return outright
 * ("pointer return — addresses not comparable") unless the manifest names the
 * caller-owned buffer parameter the result must point into, and the worker then
 * compares the ELEMENT INDEX on each side rather than two unrelated process
 * addresses. Every function here therefore returns either NULL or an address
 * inside its own `buf` argument — never one-past-the-end, which
 * `_relative_pointer` would report as `external@0x...` and which would differ
 * between the two builds for reasons that say nothing about the decompiler.
 *
 * TWO NEGATIVE CONTROLS:
 *
 *   `ptr199_find_index` runs `ptr199_find_i32`'s scan and returns the INDEX as
 *   an `int32_t`. Turning a returned pointer into an index is the single most
 *   plausible mis-recovery here, and it is a recovery that satisfies this
 *   control while failing every positive case; keeping both side by side is
 *   what tells the two apart.
 *
 *   `ptr199_first_element` ignores `key` entirely and returns `&buf[0]` after
 *   reading the buffer. A recovery that answers "some address inside the
 *   argument buffer" — the shape a dropped comparison produces — passes the
 *   positives by luck on the vectors where the match happens to be at index 0,
 *   and this control is where it stops passing.
 *
 * Every function is a pure function of a caller-owned buffer and two integers:
 * no writes, no allocation, no I/O. `n` is declared a length in the manifest so
 * it is clamped to the buffer, and the scan is a plain forward loop, so nothing
 * here can read out of bounds. */

/* Scan for `key` and return the address of the FIRST match, or NULL. The
 * canonical pointer return, and the baseline the two `void *` / `const` cases
 * are variations on. */
__attribute__((noinline)) int32_t *ptr199_find_i32(int32_t *buf, int32_t n, int32_t key) {
    int32_t i;
    if (buf == 0) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        if (buf[i] == key) {
            return &buf[i];
        }
    }
    return 0;
}

/* The same address, typed `void *`. The pointee width is not in the source, so
 * every layer has to agree on the synthetic one. */
__attribute__((noinline)) void *ptr199_find_void(int32_t *buf, int32_t n, int32_t key) {
    int32_t i;
    if (buf == 0) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        if (buf[i] == key) {
            return (void *)&buf[i];
        }
    }
    return 0;
}

/* The same address again, read-only. Scans from the END, so this is also the
 * LAST match rather than the first: a recovery that confuses the two returns a
 * different element index on any vector where `key` occurs twice. */
__attribute__((noinline)) const int32_t *ptr199_find_const(const int32_t *buf, int32_t n,
                                                           int32_t key) {
    int32_t i;
    if (buf == 0) {
        return 0;
    }
    for (i = n - 1; i >= 0; i--) {
        if (buf[i] == key) {
            return &buf[i];
        }
    }
    return 0;
}

/* An address formed by ARITHMETIC and not by a load: no element is ever read.
 * `k` is folded into range with a remainder so the result is always inside the
 * buffer and never one-past-the-end. */
__attribute__((noinline)) int32_t *ptr199_offset(int32_t *buf, int32_t n, int32_t k) {
    int32_t index;
    if (buf == 0 || n <= 0) {
        return 0;
    }
    index = k % n;
    if (index < 0) {
        index += n;
    }
    return buf + index;
}

/* CONTROL: `ptr199_find_i32`'s scan, returning the index instead of the
 * address. Passing this while failing the positives localises the defect to the
 * pointer result rather than to the search. */
__attribute__((noinline)) int32_t ptr199_find_index(int32_t *buf, int32_t n, int32_t key) {
    int32_t i;
    if (buf == 0) {
        return -1;
    }
    for (i = 0; i < n; i++) {
        if (buf[i] == key) {
            return i;
        }
    }
    return -1;
}

/* CONTROL: the result depends on WHETHER `key` occurs, never on WHERE. It runs
 * the same comparison over the same buffer as `ptr199_find_i32` and then answers
 * one of the two ENDS. A recovery that lets the match position leak into the
 * returned address — the natural way to get the positives right by accident —
 * disagrees here on every vector whose match is in the interior. */
__attribute__((noinline)) int32_t *ptr199_edge_element(int32_t *buf, int32_t n, int32_t key) {
    int32_t i;
    int32_t seen;
    if (buf == 0 || n <= 0) {
        return 0;
    }
    seen = 0;
    for (i = 0; i < n; i++) {
        if (buf[i] == key) {
            seen++;
        }
    }
    return (seen > 0) ? &buf[0] : &buf[n - 1];
}
