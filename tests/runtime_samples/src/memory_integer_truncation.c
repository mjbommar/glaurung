#include "runtime_sample.h"

struct box {
    unsigned char dst[8];
    uint32_t canary;
};

int main(int argc, char **argv) {
    struct box b = {{0}, 0x76543210};
    rs_checkpoint_if("GLAURUNG_RUNTIME_TRACE_BEGIN");
    unsigned long requested = rs_bad(argc, argv) ? 265 : 8;
    unsigned char narrowed = (unsigned char)requested;
    memset(b.dst, 0xee, narrowed > 8 ? 12 : narrowed);
    rs_checkpoint_if("GLAURUNG_RUNTIME_TRACE_END");
    return rs_result("canary", b.canary);
}
