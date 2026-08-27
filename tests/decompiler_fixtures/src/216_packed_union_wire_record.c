#include <stdint.h>

/* Bitfields inside a PACKED UNION, read back through a byte view — the shape
 * every binary protocol header actually has, and one no fixture composes.
 *
 * WHAT THE COMPOSITION COSTS. Three recovery problems interact here and none of
 * them is visible alone:
 *
 *   * a bitfield read is a load, a shift and a mask, and the field's WIDTH is
 *     encoded only in the mask constant;
 *   * a union means the same storage is read at two different types, so an
 *     object model keyed by access width sees conflicting evidence for one
 *     address rather than two disjoint objects;
 *   * `packed` removes the padding that would otherwise separate the fields,
 *     so a byte view straddles bitfield boundaries and the shift amounts stop
 *     being multiples of eight.
 *
 * A decompiler that recovers each in isolation can still produce wrong C for
 * the combination: the classic failure is folding the union's two views into
 * one field of the wider type, which compiles, runs, and silently reinterprets
 * every read.
 *
 * `90_bitfields` covers bitfield layout on its own. `91_union_type_punning`
 * covers a union on its own. `161_packed_struct_layout` covers `packed` on its
 * own. `163_wire_header_parser` parses a wire header but does it with explicit
 * shifts and masks rather than bitfields, which is a different recovery
 * problem. This fixture is the intersection, which is what real headers look
 * like.
 *
 * Bit-field layout within a unit is implementation-defined, so every function
 * here is written to be layout-AGNOSTIC: values are written through the
 * bitfield view and read back through the same view, and the byte view is only
 * ever used to observe that SOMETHING changed in a specific byte, never to
 * assert which bit. That keeps the differential valid across every target while
 * still forcing the recovery to model the storage overlap.
 */

struct __attribute__((packed)) wire_flags {
    uint8_t version : 3;
    uint8_t urgent  : 1;
    uint8_t kind    : 4;
};

union __attribute__((packed)) wire_head {
    struct wire_flags fields;
    uint8_t raw;
};

/* Write through the bitfield view, read through the same view. Layout-agnostic
 * and exact. */
__attribute__((noinline)) int32_t bitfield_roundtrip(int32_t version,
                                                     int32_t urgent,
                                                     int32_t kind) {
    union wire_head head;
    head.raw = 0;
    head.fields.version = (uint8_t)(version & 0x7);
    head.fields.urgent = (uint8_t)(urgent & 0x1);
    head.fields.kind = (uint8_t)(kind & 0xf);
    return (int32_t)head.fields.version * 100 + (int32_t)head.fields.urgent * 10 +
           (int32_t)head.fields.kind;
}

/* Write through the bitfield view, observe through the BYTE view. The exact bit
 * positions are implementation-defined, so only the population count is
 * asserted — which is layout-independent and still requires the storage overlap
 * to be modelled. */
__attribute__((noinline)) int32_t bitfield_seen_as_byte(int32_t version,
                                                        int32_t kind) {
    union wire_head head;
    head.raw = 0;
    head.fields.version = (uint8_t)(version & 0x7);
    head.fields.kind = (uint8_t)(kind & 0xf);
    return __builtin_popcount((unsigned)head.raw);
}

/* Write through the BYTE view, read through the bitfield view: the reverse
 * direction, where a folded union produces a different answer. Again only the
 * population count of the reassembled fields is compared. */
__attribute__((noinline)) int32_t byte_seen_as_bitfields(int32_t byte_value) {
    union wire_head head;
    head.raw = (uint8_t)(byte_value & 0xff);
    int32_t total = (int32_t)head.fields.version + (int32_t)head.fields.urgent +
                    (int32_t)head.fields.kind;
    return total;
}

/* A packed record of several such units, walked as an array. This is the shape
 * a TLV parser has, and it forces a stride the compiler cannot pad. */
struct __attribute__((packed)) wire_record {
    union wire_head head;
    uint16_t length;
    uint8_t tag;
};

__attribute__((noinline)) int32_t walk_packed_records(const uint8_t *bytes,
                                                       int32_t count) {
    int32_t total = 0;
    if (bytes == 0 || count < 0 || count > 4) {
        return -1;
    }
    for (int32_t i = 0; i < count; i++) {
        struct wire_record rec;
        const uint8_t *src = bytes + (int32_t)sizeof(struct wire_record) * i;
        /* Byte-wise copy: no unaligned load, valid on every target. */
        for (uint32_t b = 0; b < sizeof(struct wire_record); b++) {
            ((uint8_t *)&rec)[b] = src[b];
        }
        total += (int32_t)rec.head.fields.kind;
        total += (int32_t)(rec.length & 0xff);
        total += (int32_t)rec.tag;
    }
    return total;
}

/* CONTROL: the same three fields as ordinary members, with no bitfields, no
 * union and no packing. If this fails, the defect is in struct recovery
 * generally rather than in the composition. */
struct plain_head {
    uint8_t version;
    uint8_t urgent;
    uint8_t kind;
};

__attribute__((noinline)) int32_t plain_struct_control(int32_t version,
                                                       int32_t urgent,
                                                       int32_t kind) {
    struct plain_head head;
    head.version = (uint8_t)(version & 0x7);
    head.urgent = (uint8_t)(urgent & 0x1);
    head.kind = (uint8_t)(kind & 0xf);
    return (int32_t)head.version * 100 + (int32_t)head.urgent * 10 +
           (int32_t)head.kind;
}
