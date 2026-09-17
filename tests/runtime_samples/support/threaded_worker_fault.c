#include <pthread.h>
#include <stdint.h>

static void *faulting_worker(void *unused) {
    (void)unused;
    volatile uintptr_t address = 0;
    volatile uint32_t *target = (volatile uint32_t *)address;
    *target = 0x47524c47U;
    return NULL;
}

int main(void) {
    pthread_t worker;
    if (pthread_create(&worker, NULL, faulting_worker, NULL) != 0) {
        return 2;
    }
    if (pthread_join(worker, NULL) != 0) {
        return 3;
    }
    return 4;
}
