#include <stdint.h>

/* The same machine bits mean different things at different use sites, and a
 * decompiler that decides from the bits alone gets exactly half of this file
 * wrong.
 *
 * Targets `program::references` (the use-site reference resolver) and its first
 * consumer in `ir::readonly_fold`.
 *
 * POSITIVE — `MC193_NAMES` is a `static const char *const` table. Under
 * `-shared -fPIC` it lands in `.data.rel.ro` with one `R_*_RELATIVE` per slot,
 * so each word is a *reference* that the loader writes, not a datum. Two
 * readings are available and both are wrong:
 *
 *   - leave it alone            -> `*(long *)(0x3da0 + i * 8)`
 *   - read the bytes as numbers -> `(i == 0) ? 0x200b : ...`
 *
 * Neither address exists in the rebuilt unit, so both crash or return garbage.
 * Only "slot i holds the string \"alpha\"" recompiles and executes.
 *
 * CONTROL — `MC193_OFFSETS` has the same shape (a `static const` table indexed
 * by a masked argument) and its entries are deliberately chosen to look like
 * addresses in this object's own mapped range. They are numbers. A symbolizer
 * that promotes a constant because it falls inside a mapped section turns these
 * into pointers and the arithmetic below returns something else. So does
 * `mc193_scaled_constant`, where the address-shaped value is an immediate the
 * function multiplies.
 *
 * The pairing is what gives the fixture teeth in both directions: a decompiler
 * that transforms nothing fails the positives, and one that symbolizes on
 * mapped-range membership fails the controls.
 */

#define MC193_SLOT_LENGTH 0
#define MC193_SLOT_FIRST 1
#define MC193_SLOT_LAST 2

/* Distinct lengths, distinct first and last bytes, and no entry is a suffix of
 * another: a table that resolves to the wrong slot cannot produce the right
 * observables by accident. Every entry clears the string pool's three-character
 * floor, because one unproved slot correctly aborts the whole fold. */
static const char *const MC193_NAMES[4] = {"alpha", "bravo!", "charlie", "kilo"};

/* Every one of these values is inside a PT_LOAD of this very object in all four
 * lanes -- checked against `readelf -lW`, whose common mapped ranges are
 * 0x0-0x5c8, 0x1000-0x1271, 0x2000-0x214c and 0x3e50-0x4028. They are still
 * integers, and the arithmetic below is the only thing that says so. */
static const uint32_t MC193_OFFSETS[4] = {0x00f0u, 0x1140u, 0x2008u, 0x2100u};

/* POSITIVE: the selected slot must be the real string, or the length is not
 * the source's length. */
__attribute__((noinline)) int32_t mc193_name_length(int32_t which) {
    const char *name = MC193_NAMES[which & 3];
    int32_t length = 0;
    while (name[length] != '\0') {
        length += 1;
    }
    return length;
}

/* POSITIVE: every observable byte of the selected string, written into the
 * caller's buffer so a table that resolves to the wrong entry is visible
 * rather than merely a different total. */
__attribute__((noinline)) int32_t mc193_name_bytes(int32_t which, int32_t *witness) {
    const char *name;
    int32_t length = 0;
    if (witness == 0) {
        return -1;
    }
    name = MC193_NAMES[which & 3];
    while (name[length] != '\0') {
        length += 1;
    }
    witness[MC193_SLOT_LENGTH] = length;
    witness[MC193_SLOT_FIRST] = (int32_t)(uint8_t)name[0];
    witness[MC193_SLOT_LAST] = (int32_t)(uint8_t)name[length - 1];
    return witness[MC193_SLOT_FIRST] * 31 + witness[MC193_SLOT_LAST];
}

/* POSITIVE: a slot read whose result is compared, not dereferenced. The two
 * entries are distinct strings, so a table that collapses them changes the
 * answer. */
__attribute__((noinline)) int32_t mc193_names_differ(int32_t left, int32_t right) {
    const char *a = MC193_NAMES[left & 3];
    const char *b = MC193_NAMES[right & 3];
    int32_t index = 0;
    while (a[index] != '\0' && b[index] != '\0') {
        if (a[index] != b[index]) {
            return index + 1;
        }
        index += 1;
    }
    return (a[index] == b[index]) ? 0 : -(index + 1);
}

/* CONTROL: address-shaped table entries consumed by arithmetic. Must remain
 * numbers. */
__attribute__((noinline)) uint32_t mc193_offset_sum(uint32_t which) {
    uint32_t first = MC193_OFFSETS[which & 3u];
    uint32_t second = MC193_OFFSETS[(which + 1u) & 3u];
    return first * 3u + second;
}

/* CONTROL: an address-shaped table entry compared against a caller value. A
 * promoted entry changes which comparisons hold. */
__attribute__((noinline)) int32_t mc193_offset_matches(uint32_t which, uint32_t probe) {
    uint32_t entry = MC193_OFFSETS[which & 3u];
    if (entry == probe) {
        return 1;
    }
    return (entry > probe) ? 2 : 3;
}

/* CONTROL: an address-shaped immediate, never loaded from anywhere, used only
 * as a multiplier and an addend. */
__attribute__((noinline)) uint64_t mc193_scaled_constant(uint64_t value) {
    return value * 0x2008u + 0x1140u;
}
