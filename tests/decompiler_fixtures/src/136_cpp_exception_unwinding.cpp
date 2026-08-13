/* 136_cpp_exception_unwinding.cpp
 *
 * Throwing runs the personality routine over .eh_frame / .gcc_except_table,
 * selecting a landing pad by the thrown type and running every destructor
 * between throw and catch. None of that control flow appears in the ordinary
 * CFG: the unwind edges live in metadata, and the cleanup calls are only
 * reachable through them.
 */
#include <stdint.h>

namespace {

struct Marker {
    int32_t *log;
    int32_t slot;
    int32_t value;
    Marker(int32_t *l, int32_t s, int32_t v) : log(l), slot(s), value(v) {}
    ~Marker() { log[slot] = value; }
};

struct SmallError {
    int32_t code;
};

struct LargeError {
    int32_t code;
    int32_t detail[4];
};

int32_t may_throw(int32_t selector) {
    if (selector == 1) {
        SmallError error;
        error.code = 7;
        throw error;
    }
    if (selector == 2) {
        LargeError error;
        error.code = 9;
        error.detail[0] = 1;
        error.detail[1] = 2;
        error.detail[2] = 3;
        error.detail[3] = 4;
        throw error;
    }
    if (selector == 3) {
        throw 42; /* a plain int */
    }
    return selector * 100;
}

}  // namespace

extern "C" int32_t cpp_catch_by_type(int32_t selector) {
    try {
        return may_throw(selector & 3);
    } catch (const SmallError &error) {
        return 1000 + error.code;
    } catch (const LargeError &error) {
        return 2000 + error.code + error.detail[3];
    } catch (int value) {
        return 3000 + value;
    }
}

extern "C" int32_t cpp_destructors_run_while_unwinding(int32_t *log,
                                                       int32_t selector) {
    if (log == 0) {
        return -1;
    }
    log[0] = 0;
    log[1] = 0;
    log[2] = 0;
    try {
        Marker outer(log, 0, 11);
        {
            Marker inner(log, 1, 22);
            may_throw(selector & 3);
            log[2] = 33; /* skipped when may_throw actually throws */
        }
    } catch (...) {
        /* Both markers have already been destroyed, innermost first. */
        return log[0] * 100 + log[1] * 10 + log[2];
    }
    return log[0] * 100 + log[1] * 10 + log[2];
}

extern "C" int32_t cpp_rethrow_and_nest(int32_t selector) {
    try {
        try {
            may_throw(selector & 3);
        } catch (const SmallError &) {
            throw; /* rethrow the in-flight exception */
        } catch (int value) {
            throw SmallError{value}; /* replace it with a different type */
        }
    } catch (const SmallError &error) {
        return 500 + error.code;
    } catch (...) {
        return 600;
    }
    return 0;
}
