/* 04_switch_shapes.c
 *
 * Switch-shape fixture. Every function is a pure integer function whose result
 * depends on the EXACT switch structure a correct decompilation must recover:
 * the true case constants (not positional 0/1/2/... placeholders), negative and
 * sparse labels, shared bodies, explicit fallthrough, default handling, and a
 * switch nested inside a loop. Each reachable case produces a UNIQUE constant,
 * so a fabricated `case 0 / case 1` discriminant, a positional relabel, or a
 * placeholder dispatch sends some input to the wrong arm — which an
 * execution-differential test catches.
 *
 * Targets review #4 (switch structuring). Keep every function pure (no globals,
 * no libc) and deterministic. Each comment states the exact discriminant and
 * the case constants an honest decompiler must recover.
 */
#include <stdint.h>

/* Dense jump-table switch. Discriminant: (x & 7), a contiguous 0..7 index that
 * a compiler lowers to a jump table. An honest decompiler must recover cases
 * 0,1,2,3,4,5,6,7 with these EXACT distinct return constants. */
int dense_jumptable(unsigned x) {
    switch (x & 7u) {
        case 0: return 100;
        case 1: return 111;
        case 2: return 122;
        case 3: return 133;
        case 4: return 144;
        case 5: return 155;
        case 6: return 166;
        case 7: return 177;
    }
    return -1;   /* unreachable given the mask, but keeps the type happy */
}

/* Dense table that computes rather than returns constants, still 0..7. */
int dense_compute(unsigned x, int y) {
    int r;
    switch (x & 7u) {
        case 0: r = y + 1; break;
        case 1: r = y - 1; break;
        case 2: r = y * 2; break;
        case 3: r = y * 3; break;
        case 4: r = y ^ 0x5A; break;
        case 5: r = y << 1; break;
        case 6: r = ~y; break;
        case 7: r = y & 0x0F; break;
        default: r = 0; break;
    }
    return r;
}

/* Sparse switch. Discriminant: x itself. Cases 1, 5, 17, 100 — large, non-
 * contiguous, non-zero labels. This tests that the REAL case constants are
 * recovered, NOT positional 0/1/2/3. A decompiler that emits case 0..3 maps
 * every input to the wrong arm. */
int sparse_switch(int x) {
    switch (x) {
        case 1:   return 2001;
        case 5:   return 2005;
        case 17:  return 2017;
        case 100: return 2100;
        default:  return 2999;
    }
}

/* Sparse switch with widely spread labels forcing a binary-search or compare
 * chain lowering. Discriminant: x. Cases 3, 250, 5000, 65537. */
int sparse_wide(int x) {
    switch (x) {
        case 3:     return 30;
        case 250:   return 2500;
        case 5000:  return 50000;
        case 65537: return 655370;
        default:    return -7;
    }
}

/* Negative case values. Discriminant: x. Cases -3, -1, 0, 2 — a decompiler must
 * recover the signed labels, not treat them as large unsigned indices. */
int negative_cases(int x) {
    switch (x) {
        case -3: return 303;
        case -1: return 301;
        case 0:  return 300;
        case 2:  return 302;
        default: return 399;
    }
}

/* Mixed negative + sparse positive. Discriminant: x. Cases -100, -1, 7, 42. */
int negative_sparse(int x) {
    switch (x) {
        case -100: return 4000;
        case -1:   return 4001;
        case 7:    return 4007;
        case 42:   return 4042;
        default:   return 4999;
    }
}

/* Shared case bodies. Discriminant: (x & 7). Cases 0 and 2 fall to the SAME
 * body (return 500); cases 1 and 3 share another (return 600); everything else
 * defaults. An honest decompiler must show two labels reaching one block, not
 * duplicate or drop a label. */
int shared_bodies(unsigned x) {
    switch (x & 7u) {
        case 0:
        case 2:
            return 500;
        case 1:
        case 3:
            return 600;
        default:
            return 700;
    }
}

/* Shared bodies mixing sparse labels. Discriminant: x. Cases 10 and 20 share a
 * body; 30 and 40 share another. */
int shared_sparse(int x) {
    switch (x) {
        case 10:
        case 20:
            return 1200;
        case 30:
        case 40:
            return 3400;
        default:
            return -5;
    }
}

/* Explicit fallthrough. Discriminant: (x & 3). case 0 has NO break and flows
 * into case 1's body, so input 0 accumulates BOTH contributions. A decompiler
 * that inserts a spurious break, or drops the fallthrough edge, changes the
 * result for x&3==0. Recover: case 0 -> (+7, fallthrough), case 1 -> (+30),
 * case 2 -> (+500, break), default -> +9000. */
int explicit_fallthrough(unsigned x) {
    int r = 0;
    switch (x & 3u) {
        case 0:
            r += 7;
            /* fallthrough */
        case 1:
            r += 30;
            break;
        case 2:
            r += 500;
            break;
        default:
            r += 9000;
            break;
    }
    return r;   /* x&3==0 -> 37, ==1 -> 30, ==2 -> 500, ==3 -> 9000 */
}

/* Longer fallthrough chain. Discriminant: (x & 3). Each case adds a distinct
 * weight and falls into the next; only case 3 breaks. So the accumulated total
 * encodes exactly where the switch entered. */
int fallthrough_chain(unsigned x) {
    int r = 0;
    switch (x & 3u) {
        case 0: r += 1;
        case 1: r += 20;
        case 2: r += 300;
        case 3: r += 4000; break;
        default: r = -1;
    }
    return r;   /* 0->4321, 1->4320, 2->4300, 3->4000 */
}

/* Default-only observable behaviour. Discriminant: x. Only case 42 is special;
 * every other value takes the default. Tests that the single real label is
 * recovered and the default catch-all is not mistaken for a case. */
int default_dominant(int x) {
    switch (x) {
        case 42: return 8888;
        default: return 1111;
    }
}

/* Switch with no default: values outside the label set fall through the whole
 * statement to the trailing return. Discriminant: (x & 7). Cases 2 and 5 only. */
int no_default(unsigned x) {
    switch (x & 7u) {
        case 2: return 220;
        case 5: return 550;
    }
    return 999;   /* the implicit fall-off path */
}

/* Switch INSIDE a loop. The switch dispatches on each buffer element's low bits
 * every iteration; the accumulator threads through the loop. Discriminant per
 * iteration: (p[i] & 3), cases 0/1/2/3 each folding a distinct operation. A
 * switch hoisted out of the loop, or a mis-recovered discriminant, changes the
 * fold. The gate drives `p` as 8 random ints. */
int switch_in_loop(const int *p) {
    int s = 0;
    for (int i = 0; i < 8; i++) {
        switch (p[i] & 3) {
            case 0: s += 1; break;
            case 1: s += 10; break;
            case 2: s += 100; break;
            case 3: s += 1000; break;
        }
    }
    return s;   /* base-10 digits count how many elements hit each residue */
}

/* Switch in a loop with fallthrough and an early break out of the LOOP (not just
 * the switch). Discriminant per iteration: (p[i] & 7). case 7 breaks the loop;
 * cases 0/1 fall through together. Tests that switch-break vs loop-break are
 * distinguished. */
int switch_loop_break(const int *p) {
    int s = 0;
    int i = 0;
    for (; i < 8; i++) {
        switch (p[i] & 7) {
            case 0:
            case 1:
                s += 2;      /* shared body, then break the switch */
                break;
            case 7:
                s += 5;
                goto done;   /* leave the loop entirely */
            default:
                s += 1;
                break;
        }
    }
done:
    return s * 10 + i;   /* i records where (if) the loop broke early */
}

/* Nested switch: an outer discriminant selects a group, an inner switch refines
 * it. Recover: outer (x & 1) -> {0,1}; inner (y & 1) -> {0,1}; four distinct
 * leaf constants. */
int nested_switch(unsigned x, unsigned y) {
    switch (x & 1u) {
        case 0:
            switch (y & 1u) {
                case 0: return 6000;
                case 1: return 6001;
            }
            break;
        case 1:
            switch (y & 1u) {
                case 0: return 6010;
                case 1: return 6011;
            }
            break;
    }
    return -1;
}

/* Sparse switch returning through a shared tail after computing per-case: tests
 * that recovered case constants feed a common continuation, not duplicated
 * exits. Discriminant: x. Cases 11, 22, 33. */
int sparse_shared_tail(int x) {
    int r;
    switch (x) {
        case 11: r = 1; break;
        case 22: r = 2; break;
        case 33: r = 3; break;
        default: r = 9; break;
    }
    return r * 1000 + r * r;   /* common tail exercised by every case */
}
