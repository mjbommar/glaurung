#include "runtime_sample.h"

#include <stdlib.h>
#include <string.h>

int main(void) {
    unsigned char *object = calloc(1, 8);
    if (object == NULL)
        return 2;
    memset(object, 5, 1);

    rs_checkpoint_if("GLAURUNG_RUNTIME_TRACE_BEGIN");
    object[1] = 6;
    rs_checkpoint_if("GLAURUNG_RUNTIME_TRACE_END");
    rs_checkpoint_if("GLAURUNG_RUNTIME_POST_TRACE");
    free(object);
    return 0;
}
