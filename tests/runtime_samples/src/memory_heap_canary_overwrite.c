#include "runtime_sample.h"

int main(int argc, char **argv) {
    size_t n = 8;
    unsigned char *p = calloc(1, n + 8);
    if (p == NULL)
        return 2;
    uint32_t *canary = (uint32_t *)(p + n);
    *canary = 0x12345678;
    size_t index = rs_bad(argc, argv) ? n : n - 1;
    rs_checkpoint_if("GLAURUNG_RUNTIME_TRACE_BEGIN");
    p[index] = 0xff;
    rs_checkpoint_if("GLAURUNG_RUNTIME_TRACE_END");
    rs_checkpoint_if("GLAURUNG_RUNTIME_POST_TRACE");
    long value = *canary;
    free(p);
    return rs_result("canary", value);
}
