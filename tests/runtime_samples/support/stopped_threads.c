#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static atomic_int worker_ready;

static void *waiting_worker(void *unused) {
    (void)unused;
    atomic_store_explicit(&worker_ready, 1, memory_order_release);
    for (;;) {
        pause();
    }
}

int main(int argc, char **argv) {
    pthread_t worker;
    if (getenv("GLAURUNG_TEST_CAPTURE_SECRET") != NULL) {
        return 4;
    }
    if (argc > 1 && strcmp(argv[1], "require-env") == 0 &&
        getenv("GLAURUNG_TEST_CAPTURE_ALLOWED") == NULL) {
        return 5;
    }
    if (pthread_create(&worker, NULL, waiting_worker, NULL) != 0) {
        return 2;
    }
    while (!atomic_load_explicit(&worker_ready, memory_order_acquire)) {
        sched_yield();
    }
    raise(SIGSTOP);
    return 3;
}
