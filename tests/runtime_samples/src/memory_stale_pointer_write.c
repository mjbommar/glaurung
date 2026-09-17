#include "runtime_sample.h"

int main(int argc, char **argv) {
    unsigned char *p = calloc(16, 1);
    if (p == NULL)
        return 2;
    memset(p, 1, 1);
    if (rs_bad(argc, argv)) {
        free(p);
        memset(p, 9, 1);
        return rs_result("stale", p[0]);
    }
    long value = p[0];
    free(p);
    return rs_result("safe", value);
}
