/* 164_nested_tlv_walker.c
 *
 * Nested type-length-value, the shape that BER/DER, USB descriptors, ISO 8583,
 * Bluetooth advertising data and half of firmware-land all share:
 *
 *   node := type:u8  len:u8  value[len]
 *
 * A type with bit 7 set is a CONTAINER: its value is itself a TLV sequence,
 * walked recursively. Everything else is a leaf whose value bytes are data.
 * A sequence is well formed only if the nodes tile it EXACTLY -- no trailing
 * bytes, no node whose value runs past the end of its enclosing container.
 *
 * Why this stresses a decompiler: the bound at every step is not the buffer, it
 * is the *current container*, and that bound is re-derived on each recursion
 * from the parent's own length field. Lowered, this is a family of nearly
 * identical compares against different registers, and the recursion is a
 * self-call whose arguments (`p + body`, `vlen`, `depth + 1`) carry the whole
 * safety argument. A decompiler that reconstructs the bound from the outer
 * buffer length instead of the container length, or that loses `+ 2` when
 * advancing past a node header, emits C that walks every well-formed message
 * identically and reads out of bounds on a nested length that lies. The
 * "exactly tiles" check (-3) is what makes such a slip observable at all: with
 * a merely permissive walker, an off-by-one just silently sees a different
 * node count.
 *
 * UB notes: `len` is clamped to [0, 16] before use, so every subtraction below
 * is on small non-negative values. Recursion depth is capped at 4 and every
 * node advances the cursor by at least 2 bytes, so the walk always terminates;
 * a redundant iteration guard makes that bound explicit rather than implied.
 */
#include <stddef.h>
#include <stdint.h>

#define TLV164_MAX_BUF   16
#define TLV164_MAX_DEPTH 4
#define TLV164_CONTAINER 0x80u
#define TLV164_HDR_BYTES 2
#define TLV164_HIT_BASE  1000

/* Clamp a caller length into [0, TLV164_MAX_BUF] before any arithmetic. */
static int32_t tlv164_clamp(int32_t n) {
    if (n < 0) {
        return 0;
    }
    if (n > TLV164_MAX_BUF) {
        return TLV164_MAX_BUF;
    }
    return n;
}

/* Walk [p, p + limit) as a TLV sequence at nesting level `depth`.
 * Returns the number of nodes (>= 0) or a distinct negative code, accumulating
 * the deepest level reached in *deepest and every leaf byte into *leaf_sum. */
static int32_t tlv164_walk(const uint8_t *p, int32_t limit, int32_t depth,
                           int32_t *deepest, int32_t *leaf_sum) {
    int32_t cursor = 0;
    int32_t nodes = 0;
    int32_t guard = 0;

    if (depth > TLV164_MAX_DEPTH) {
        return -4; /* nesting deeper than this parser will follow */
    }
    if (depth > *deepest) {
        *deepest = depth;
    }

    while (cursor + TLV164_HDR_BYTES <= limit) {
        uint32_t type = (uint32_t)p[cursor];
        int32_t value_len = (int32_t)p[cursor + 1];
        int32_t body = cursor + TLV164_HDR_BYTES;

        guard++;
        if (guard > TLV164_MAX_BUF) {
            return -5; /* unreachable while every node advances >= 2 bytes */
        }
        /* The bound is the ENCLOSING CONTAINER, not the outermost buffer. */
        if (value_len > limit - body) {
            return -2;
        }
        nodes++;
        if ((type & TLV164_CONTAINER) != 0u) {
            int32_t inner =
                tlv164_walk(p + body, value_len, depth + 1, deepest, leaf_sum);
            if (inner < 0) {
                return inner;
            }
            nodes += inner;
        } else {
            int32_t i;
            for (i = 0; i < value_len; i++) {
                *leaf_sum += (int32_t)p[body + i];
            }
        }
        cursor = body + value_len;
    }
    if (cursor != limit) {
        return -3; /* trailing bytes that are not a complete node */
    }
    return nodes;
}

/* Depth-first search for the first node of type `want`, at any nesting level.
 * Returns TLV164_HIT_BASE + first value byte for a non-empty match,
 * TLV164_HIT_BASE for an empty one, 0 when absent, or a negative code. */
static int32_t tlv164_seek(const uint8_t *p, int32_t limit, int32_t depth,
                           uint32_t want) {
    int32_t cursor = 0;
    int32_t guard = 0;

    if (depth > TLV164_MAX_DEPTH) {
        return -4;
    }

    while (cursor + TLV164_HDR_BYTES <= limit) {
        uint32_t type = (uint32_t)p[cursor];
        int32_t value_len = (int32_t)p[cursor + 1];
        int32_t body = cursor + TLV164_HDR_BYTES;

        guard++;
        if (guard > TLV164_MAX_BUF) {
            return -5;
        }
        if (value_len > limit - body) {
            return -2;
        }
        if (type == want) {
            return (value_len > 0) ? TLV164_HIT_BASE + (int32_t)p[body]
                                   : TLV164_HIT_BASE;
        }
        if ((type & TLV164_CONTAINER) != 0u) {
            int32_t hit = tlv164_seek(p + body, value_len, depth + 1, want);
            if (hit != 0) {
                return hit;
            }
        }
        cursor = body + value_len;
    }
    return 0;
}

/* Total node count over the whole nesting tree, or a negative code. */
__attribute__((noinline)) int32_t
tlv164_node_count(const uint8_t *buf, int32_t len) {
    int32_t deepest = 0;
    int32_t leaf_sum = 0;

    if (buf == NULL) {
        return -1;
    }
    return tlv164_walk(buf, tlv164_clamp(len), 0, &deepest, &leaf_sum);
}

/* Deepest nesting level reached (0 for a flat sequence), or a negative code. */
__attribute__((noinline)) int32_t
tlv164_max_depth(const uint8_t *buf, int32_t len) {
    int32_t deepest = 0;
    int32_t leaf_sum = 0;
    int32_t rc;

    if (buf == NULL) {
        return -1;
    }
    rc = tlv164_walk(buf, tlv164_clamp(len), 0, &deepest, &leaf_sum);
    return (rc < 0) ? rc : deepest;
}

/* Sum of every LEAF value byte -- container headers and container payload
 * framing bytes must not contribute. Returns a positive summary or a code. */
__attribute__((noinline)) int32_t
tlv164_leaf_sum(const uint8_t *buf, int32_t len) {
    int32_t deepest = 0;
    int32_t leaf_sum = 0;
    int32_t rc;

    if (buf == NULL) {
        return -1;
    }
    rc = tlv164_walk(buf, tlv164_clamp(len), 0, &deepest, &leaf_sum);
    return (rc < 0) ? rc : (TLV164_HIT_BASE + leaf_sum * 10 + rc);
}

/* Depth-first lookup by node type. */
__attribute__((noinline)) int32_t
tlv164_find_type(const uint8_t *buf, int32_t len, int32_t want_type) {
    if (buf == NULL) {
        return -1;
    }
    return tlv164_seek(buf, tlv164_clamp(len), 0,
                       (uint32_t)want_type & 0xFFu);
}

/* Emit container{leaf} so the accepting path is reachable without a hand-built
 * vector. Returns the total encoded size, or a negative code. */
__attribute__((noinline)) int32_t
tlv164_encode_nested(uint8_t *out, int32_t out_len, int32_t inner_type,
                     int32_t inner_len) {
    int32_t room = tlv164_clamp(out_len);
    int32_t value_len = inner_len;
    int32_t total;
    int32_t i;

    if (out == NULL) {
        return -1;
    }
    if (value_len < 0) {
        value_len = 0;
    }
    if (value_len > 4) {
        value_len = 4;
    }
    total = TLV164_HDR_BYTES + TLV164_HDR_BYTES + value_len;
    if (room < total) {
        return -2;
    }
    out[0] = 0x81u;                                   /* container type */
    out[1] = (uint8_t)(TLV164_HDR_BYTES + value_len); /* container length */
    /* Clear bit 7 so the inner node is always a leaf, whatever was asked. */
    out[2] = (uint8_t)((uint32_t)inner_type & 0x7Fu);
    out[3] = (uint8_t)value_len;
    for (i = 0; i < value_len; i++) {
        out[TLV164_HDR_BYTES + TLV164_HDR_BYTES + i] =
            (uint8_t)(0x10u + (uint32_t)i);
    }
    return total;
}
