#include "runtime_sample.h"

RS_NOINLINE static void rs_copy(char *destination, const char *source,
                                size_t byte_len) {
    memcpy(destination, source, byte_len);
}

RS_NOINLINE static void rs_move(char *destination, const char *source,
                                size_t byte_len) {
    memmove(destination, source, byte_len);
}

int main(int argc, char **argv) {
    char b[16] = "abcdefghijk";
    rs_checkpoint_if("GLAURUNG_RUNTIME_TRACE_BEGIN");
    if (rs_bad(argc, argv)) {
        rs_copy(b + 1, b, 8);
    } else {
        rs_move(b + 1, b, 8);
    }
    rs_checkpoint_if("GLAURUNG_RUNTIME_TRACE_END");
    return rs_result("overlap", b[2]);
}
