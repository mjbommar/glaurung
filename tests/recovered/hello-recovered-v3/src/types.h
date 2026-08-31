// src/types.h
// Canonical type declarations recovered from binary.
// Each struct/class/enum is the longest declaration the
// rewriter emitted across any function — picked by
// _merge_type_decls so per-function copies don't fight.
#pragma once

class HelloWorld {
public:
    void printMessage();

    /* fields recovered from cross-function uses: */
    int call_count; /* TODO: refine type */
    void *message; /* TODO: refine type */
};
