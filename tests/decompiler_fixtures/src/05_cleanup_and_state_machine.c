/* 05_cleanup_and_state_machine.c
 *
 * Control-flow closure fixture: `goto cleanup` ladders, cold error blocks,
 * retry loops (backward gotos), and a small protocol state machine. The target
 * bug class is mis-structured cross-block flow — a decompiler that drops a
 * cleanup edge, folds two error arms together, or mis-orders the state
 * transitions produces a different return the moment an input exercises the
 * affected path.
 *
 * Targets review #3 / #5 (cleanup ladders + control-flow join structuring).
 * Key property: every local `goto` resolves to an emitted label — no dangling
 * gotos, every cold block is reachable via some input. Each failure path
 * returns a DISTINCT negative code; success returns a positive value derived
 * from the input. All functions are differential-testable: int / const uint8_t*
 * arguments, int return, no libc.
 */
#include <stdint.h>

/* Resource-acquisition-style validation ladder. Several conditions are checked
 * in sequence; each failure jumps into a cleanup ladder that unwinds the
 * "acquired" state (modeled by an accumulator that each stage adjusts) and
 * returns a distinct negative error code. Success returns a positive value
 * derived from the input bytes.
 *
 * A bounded retry loop sits in the middle: a transient condition on one byte
 * jumps backward to `retry` up to a fixed number of attempts before giving up
 * through the cleanup ladder. */
int process(const uint8_t *in, int n) {
    int acc = 0;
    int stage = 0;   /* how far we "acquired"; cleanup unwinds by stage */
    int attempts = 0;

    if (in == 0)
        goto fail_null;      /* nothing acquired yet */
    if (n < 4)
        goto fail_short;     /* nothing acquired yet */

    /* Stage 1: header byte must be even. */
    stage = 1;
    if ((in[0] & 1) != 0)
        goto fail_hdr;
    acc += in[0];

retry:
    /* Stage 2 with retry: in[1] must be non-zero. If it is zero we "retry"
     * by folding in the next attempt's contribution; after 3 attempts we fail
     * through the cleanup ladder. */
    if (in[1] == 0) {
        attempts++;
        if (attempts < 3) {
            acc += 1;        /* transient backoff contribution */
            goto retry;
        }
        goto fail_retry;     /* exhausted retries: stage 1 acquired */
    }

    /* Stage 2 acquired. */
    stage = 2;
    acc += in[1] * 2;

    /* Stage 3: in[2] bounds the payload nibble. */
    stage = 3;
    if (in[2] > 0x7F)
        goto fail_range;
    acc += in[2] * 3;

    /* Stage 4: checksum-style consistency across the first four bytes. */
    stage = 4;
    {
        int sum = in[0] + in[1] + in[2] + in[3];
        if ((sum & 0xFF) == 0xEE)
            goto fail_checksum;
        acc += in[3] * 4;
    }

    /* Success: a positive value that folds in the stage reached and the
     * accumulated contributions, kept in a modest positive range. */
    return 1000 + (acc & 0x3FF) + stage;

    /* --- cold cleanup ladder: unwinds by falling through, each entry point
     *     releases exactly the resources acquired up to its stage. --- */
fail_checksum:
    acc -= in[3] * 4;        /* release stage 4 */
    /* fall through */
fail_range:
    if (stage >= 3)
        acc -= in[2] * 3;    /* release stage 3 */
    /* fall through */
fail_retry:
fail_hdr:
    if (stage >= 1)
        acc -= in[0];        /* release stage 1 */
    /* distinct codes for the ladder entry points that share the tail */
    if (stage == 4) return -40;
    if (stage == 3) return -30;
    if (attempts >= 3) return -25;   /* fail_retry entry */
    return -10;                       /* fail_hdr entry */

fail_short:
    return -2;
fail_null:
    return -1;
}

/* Protocol state machine: walk `input` advancing IDLE -> HDR -> BODY -> DONE.
 * The byte sequence drives the transitions; the return code depends on which
 * state the walk ends in and how much body was consumed. If a decompiler
 * mis-structures the state dispatch (e.g. swaps two case arms or drops the
 * fallthrough from HDR to BODY) the return diverges for crafted inputs. */
int fsm(const uint8_t *input, int len) {
    enum { S_IDLE = 0, S_HDR = 1, S_BODY = 2, S_DONE = 3, S_ERR = 4 };
    int state = S_IDLE;
    int body_count = 0;
    int checksum = 0;
    int i = 0;

    if (input == 0 || len <= 0)
        return -100;

    while (i < len) {
        uint8_t b = input[i];
        switch (state) {
        case S_IDLE:
            /* Start-of-message marker. */
            if (b == 0xA5)
                state = S_HDR;
            else if (b == 0x00)
                state = S_IDLE;      /* idle padding, stay */
            else
                goto machine_error;
            break;
        case S_HDR:
            /* Header carries the declared body length in the low nibble. */
            if (b == 0xFF)
                goto machine_error;  /* reserved header */
            body_count = (b & 0x0F);
            if (body_count == 0)
                state = S_DONE;      /* empty body: jump straight to DONE */
            else
                state = S_BODY;
            checksum = b;
            break;
        case S_BODY:
            checksum += b;
            body_count--;
            if (body_count == 0)
                state = S_DONE;
            /* else remain in S_BODY consuming more bytes */
            break;
        case S_DONE:
            /* Trailer byte must match the low byte of the checksum. */
            if (b == (uint8_t)(checksum & 0xFF))
                return 200 + (checksum & 0x3F);   /* clean finish */
            else
                return -201;                       /* bad trailer */
        default:
            goto machine_error;
        }
        i++;
    }

    /* Ran out of input: distinct code per terminal state so a mis-structured
     * transition surfaces. */
    if (state == S_DONE) return 150;      /* reached DONE, no trailer seen */
    if (state == S_BODY) return -150;     /* truncated body */
    if (state == S_HDR)  return -140;     /* header without body */
    return -130;                          /* still idle */

machine_error:
    return -110 - state;                  /* distinct per originating state */
}
