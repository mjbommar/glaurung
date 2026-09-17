#include "runtime_sample.h"

#include <stdlib.h>
#include <string.h>

int main(void) {
    unsigned char *first = calloc(1, 8);
    unsigned char *second = calloc(1, 8);
    if (first == NULL || second == NULL)
        return 2;

    rs_checkpoint_if("GLAURUNG_RUNTIME_TRACE_BEGIN");
    first[0] = 1;
    rs_checkpoint_if("GLAURUNG_RUNTIME_TRACE_END");
    memset(first, 2, 1);
    memset(second, 3, 1);
    rs_checkpoint_if("GLAURUNG_RUNTIME_POST_TRACE");
    free(second);
    free(first);
    return 0;
}
