// hello/core/core.c
// Recovered from hello-gcc-O2 by glaurung source-recovery

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief Prints the object's stored message to standard output and increments its print counter.
 *
 * Writes `this->message` to `std::cout` followed by `std::endl` (which also flushes
 * the stream), then increments the `print_count` field by one to record that the
 * message has been emitted.
 *
 * @param this Pointer to the HelloWorld instance whose message is to be printed.
 *             Must be non-null; `this->message` must be a valid `std::string` and
 *             `this->print_count` must be a writable `int`.
 *
 * @return None.
 *
 * @note This function has observable side effects: it performs I/O on `std::cout`
 *       and mutates `this->print_count`. It is not thread-safe with respect to
 *       concurrent calls on the same object.
 */
#include <iostream>
#include <string>

struct HelloWorld {
    std::string message;      // offset 0x00 (pointer) / 0x08 (size/end for SSO layout)
    int         print_count;  // offset 0x20
};

void HelloWorld_printMessage(HelloWorld *this)
{
    std::cout << this->message << std::endl;
    this->print_count++;
}


fn _ZNKSt5ctypeIcE8do_widenEc {
    nop;
    return arg1;
}

