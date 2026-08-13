/* 139_cpp_object_lifetime.cpp
 *
 * Destructor ordering is fully specified: reverse of construction, per scope,
 * on every exit path including early returns. Arrays destroy back to front, and
 * a partially constructed array destroys only the elements that finished. Each
 * of those is a generated loop with no source-level counterpart.
 */
#include <stdint.h>

namespace {

struct Recorder {
    int32_t *log;
    int32_t *cursor;
    int32_t id;
    Recorder(int32_t *l, int32_t *c, int32_t identifier)
        : log(l), cursor(c), id(identifier) {}
    ~Recorder() {
        if (*cursor < 8) {
            log[*cursor] = id;
            *cursor += 1;
        }
    }
};

struct Counted {
    static int32_t live;
    int32_t id;
    Counted() : id(0) { live += 1; }
    ~Counted() { live -= 1; }
};

int32_t Counted::live = 0;

}  // namespace

extern "C" int32_t cpp_destruction_order(int32_t *log, int32_t which) {
    int32_t cursor = 0;
    if (log == 0) {
        return -1;
    }
    for (int32_t index = 0; index < 8; ++index) {
        log[index] = -1;
    }
    {
        Recorder first(log, &cursor, 1);
        Recorder second(log, &cursor, 2);
        if (which & 1) {
            Recorder conditional(log, &cursor, 3);
            /* Early return still destroys all three, innermost first. */
            return cursor * 1000 + log[0] * 100;
        }
        Recorder third(log, &cursor, 4);
    }
    /* Destroyed 4, 2, 1 in that order. */
    return log[0] * 100 + log[1] * 10 + log[2];
}

extern "C" int32_t cpp_array_destruction(int32_t *log, int32_t count) {
    int32_t cursor = 0;
    if (log == 0 || count < 0 || count > 4) {
        return -1;
    }
    for (int32_t index = 0; index < 8; ++index) {
        log[index] = -1;
    }
    {
        /* Constructed front to back, destroyed back to front. */
        Recorder recorders[3] = {Recorder(log, &cursor, 10),
                                 Recorder(log, &cursor, 20),
                                 Recorder(log, &cursor, 30)};
        (void)recorders;
    }
    return log[0] * 100 + log[1] * 10 + log[2];
}

extern "C" int32_t cpp_live_object_count(int32_t depth) {
    if (depth < 0 || depth > 4) {
        return -1;
    }
    {
        Counted outer;
        (void)outer;
        if (depth > 0) {
            Counted inner;
            (void)inner;
            if (depth > 1) {
                Counted deepest;
                (void)deepest;
                return Counted::live;
            }
            return Counted::live;
        }
        return Counted::live;
    }
}
