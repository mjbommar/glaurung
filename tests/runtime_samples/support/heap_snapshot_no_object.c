#include "runtime_sample.h"

int main(void) {
    rs_checkpoint_if("GLAURUNG_RUNTIME_TRACE_BEGIN");
    rs_checkpoint_if("GLAURUNG_RUNTIME_TRACE_END");
    rs_checkpoint_if("GLAURUNG_RUNTIME_POST_TRACE");
    return 0;
}
