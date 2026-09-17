#include "runtime_sample.h"

struct box {
    char dst[8];
    uint32_t canary;
};

RS_NOINLINE static int rs_format(char *dst, const char *format,
                                 const char *source) {
    return sprintf(dst, format, source);
}

int main(int argc, char **argv) {
    struct box b = {{0}, 0x66778899};
    char good_source[] = "ok";
    char bad_source[] = "0123456789AB";
    char format[] = "%s";
    const char *source = rs_bad(argc, argv) ? bad_source : good_source;
    rs_checkpoint_if("GLAURUNG_RUNTIME_TRACE_BEGIN");
    (void)rs_format(b.dst, format, source);
    rs_checkpoint_if("GLAURUNG_RUNTIME_TRACE_END");
    return rs_result("canary", b.canary);
}
