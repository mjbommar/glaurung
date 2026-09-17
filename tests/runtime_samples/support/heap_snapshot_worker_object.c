#include "runtime_sample.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

static void *worker(void *unused) {
    (void)unused;
    unsigned char *object = calloc(1, 8);
    if (object == NULL)
        return (void *)1;
    memset(object, 4, 1);
    free(object);
    return NULL;
}

int main(void) {
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, NULL) != 0)
        return 2;
    void *result = NULL;
    if (pthread_join(thread, &result) != 0 || result != NULL)
        return 3;

    rs_checkpoint_if("GLAURUNG_RUNTIME_TRACE_BEGIN");
    rs_checkpoint_if("GLAURUNG_RUNTIME_TRACE_END");
    rs_checkpoint_if("GLAURUNG_RUNTIME_POST_TRACE");
    return 0;
}
