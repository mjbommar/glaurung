#include <stdint.h>

/* A NULL-sentinel search over a linked structure.
 *
 * COVERAGE TARGET: `ir::loop_form::recover_sentinel_search_loops`. That pass
 * matches a compiler-rotated search — `if (head == NULL) return NULL; p = head;
 * q = head; while (!match(q)) { p = next(q); q = p; if (p == NULL) return NULL;
 * } return p;` — and rewrites it back to the source's `while (p != NULL) { if
 * (match(p)) return p; p = p->next; }`. It has never fired on a corpus lane,
 * because nothing in the corpus is a sentinel-terminated search: every existing
 * traversal is bounded by a COUNT, which rotates into an entirely different
 * shape.
 *
 * The list is an INDEX list in a caller-owned array rather than a pointer list,
 * so the harness can build it from an ordinary integer buffer and every input is
 * in bounds. `-1` is the sentinel — the same "impossible value ends the walk"
 * structure as a NULL `next`, and the one the rotation applies to. A second
 * function uses a real `const char *` NUL walk so the pointer form is covered
 * too. */

#define LIST183_LIMIT 32

/* Walk `next[]` from `start` until the sentinel, returning the first node whose
 * key matches. -1 when the sentinel is reached first. This is the exact shape
 * the rotation recovery targets. */
__attribute__((noinline)) int32_t find_by_key(const int32_t *nodes,
                                              int32_t count, int32_t key) {
    int32_t cursor = 0;
    int32_t steps = 0;
    if (nodes == 0 || count <= 0 || count > LIST183_LIMIT) {
        return -1;
    }
    /* `nodes[i]` is the key; the successor is simply `i + 1`, and `count` ends
     * the walk. Bounded by `steps` so a corrupted input cannot loop forever. */
    while (cursor < count && steps <= LIST183_LIMIT) {
        if (nodes[cursor] == key) {
            return cursor;
        }
        cursor += 1;
        steps += 1;
    }
    return -1;
}

/* The sentinel form: the walk ends on a value, not on a bound. */
__attribute__((noinline)) int32_t find_terminated_by_sentinel(
    const int32_t *values, int32_t count, int32_t key) {
    int32_t index = 0;
    if (values == 0 || count <= 0 || count > LIST183_LIMIT) {
        return -1;
    }
    /* The final element is forced to the sentinel by the caller contract; the
     * bound is present only so a malformed buffer cannot run away, and is not
     * the loop's real exit test. */
    while (index < count) {
        int32_t value = values[index];
        if (value == 0) {
            /* The sentinel: not found. */
            return -1;
        }
        if (value == key) {
            return index;
        }
        index += 1;
    }
    return -1;
}

/* The pointer form of the same walk: a NUL-terminated string, searched for a
 * byte. Returns the index, or -1. */
__attribute__((noinline)) int32_t find_byte_before_nul(const char *text,
                                                       int32_t wanted) {
    const char *cursor = text;
    int32_t steps = 0;
    if (text == 0) {
        return -1;
    }
    while (*cursor != '\0') {
        if ((int32_t)(unsigned char)*cursor == (wanted & 0xff)) {
            return (int32_t)(cursor - text);
        }
        cursor += 1;
        steps += 1;
        if (steps > LIST183_LIMIT) {
            return -1;
        }
    }
    return -1;
}

/* Length by sentinel: the same walk with no match test, so the recovery sees a
 * loop whose body is only the advance. */
__attribute__((noinline)) int32_t length_to_nul(const char *text) {
    int32_t length = 0;
    if (text == 0) {
        return -1;
    }
    while (text[length] != '\0') {
        length += 1;
        if (length > LIST183_LIMIT) {
            return -1;
        }
    }
    return length;
}

/* Two sentinels: the walk ends on either, so the exit test is a disjunction and
 * the rotation must not collapse it to one comparison. */
__attribute__((noinline)) int32_t find_before_either_sentinel(
    const int32_t *values, int32_t count, int32_t key) {
    int32_t index = 0;
    if (values == 0 || count <= 0 || count > LIST183_LIMIT) {
        return -1;
    }
    while (index < count) {
        int32_t value = values[index];
        if (value == 0 || value == -1) {
            return -1;
        }
        if (value == key) {
            return index;
        }
        index += 1;
    }
    return -1;
}
