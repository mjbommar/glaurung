/* vulnparse.c — deliberately vulnerable length-prefixed parser.
 *
 * Hand-crafted CWE-119 / CWE-787 demo: parse_record() copies
 * `declared_len` bytes from caller-supplied input into a fixed
 * 64-byte stack buffer. The "bounds check" verifies that the input
 * buffer is long enough to read declared_len bytes — but does NOT
 * verify that the *destination* buffer (`buf`) is large enough.
 *
 * declared_len is a uint8_t (0..255), so an attacker who controls
 * the first byte of input can force memcpy to write up to 255 bytes
 * into a 64-byte buffer, smashing saved registers and the return
 * address that follow.
 *
 * Used in docs/demos/demo-2-vulnerability-hunting.md.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void parse_record(const unsigned char *input, size_t total_len) {
    char buf[64];
    if (total_len < 1) return;
    unsigned char declared_len = input[0];

    /* This check only validates that the input buffer has enough
       bytes to read; it does NOT validate that buf is big enough
       to receive them. CWE-119 — bounds vs source, not bounds vs
       destination. */
    if ((size_t)declared_len > total_len - 1) {
        fprintf(stderr, "short input\n");
        return;
    }

    memcpy(buf, input + 1, declared_len);
    buf[declared_len] = '\0';
    printf("record: %s\n", buf);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <input-bytes>\n", argv[0]);
        return 1;
    }
    /* For demo simplicity we treat argv[1] as the raw packet. The
       first byte is the declared length; the rest is the body. */
    const unsigned char *input = (const unsigned char *)argv[1];
    size_t total_len = strlen(argv[1]);
    parse_record(input, total_len);
    return 0;
}
