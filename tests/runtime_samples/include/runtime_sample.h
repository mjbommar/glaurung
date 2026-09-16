#ifndef GLAURUNG_RUNTIME_SAMPLE_H
#define GLAURUNG_RUNTIME_SAMPLE_H

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__GNUC__) || defined(__clang__)
#define RS_NOINLINE __attribute__((noinline))
#else
#define RS_NOINLINE
#endif

#if defined(__GNUC__) || defined(__clang__)
__attribute__((constructor)) static void rs_entry_checkpoint(void) {
    if (getenv("GLAURUNG_RUNTIME_CHECKPOINT_ENTRY") != NULL) {
        fflush(NULL);
        raise(SIGSTOP);
    }
}
#endif

static int rs_bad(int argc, char **argv) {
    return argc > 1 && strcmp(argv[1], "bad") == 0;
}

static unsigned long rs_number(int argc, char **argv, unsigned long fallback) {
    if (argc <= 2) return fallback;
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(argv[2], &end, 0);
    return errno == 0 && end != argv[2] && *end == '\0' ? value : fallback;
}

static void rs_checkpoint(void) {
    if (getenv("GLAURUNG_RUNTIME_CHECKPOINT") != NULL) {
        fflush(NULL);
        raise(SIGSTOP);
    }
}

static int rs_result(const char *label, long value) {
    printf("RESULT %s %ld\n", label, value);
    fflush(stdout);
    rs_checkpoint();
    return 0;
}

#endif
