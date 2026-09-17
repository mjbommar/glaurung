#include "runtime_sample.h"

int main(int argc, char **argv) {
    size_t n = rs_bad(argc, argv) ? 8 : 16;
    unsigned char *p = calloc(1, n + 8);
    uint32_t *canary = (uint32_t *)(p + n);
    rs_checkpoint_if("GLAURUNG_RUNTIME_TRACE_BEGIN");
    *canary = 0x24681357;
    rs_checkpoint_if("GLAURUNG_RUNTIME_TRACE_END");
    memset(p, 0xaa, 16);
    rs_checkpoint_if("GLAURUNG_RUNTIME_POST_TRACE");
    long value = *canary;
    free(p);
    return rs_result("canary", value);
}
