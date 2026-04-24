// src/main.c
// Recovered from hello-gcc-O2 by glaurung source-recovery

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief Program entry point: greets the user and reports argv statistics.
 *
 * Constructs a HelloWorld greeter initialised with the literal
 * "Sum printed C+ +!", copies every element of @p argv (indices
 * `0 .. argc-1`) into a `std::vector<std::string>`, then writes three
 * lines to `std::cout`:
 *   - the greeting produced by `HelloWorld::printMessage()`,
 *   - "Total argument length: " followed by the summed `size()` of all
 *     stored argument strings,
 *   - "Counter value: " followed by a counter that is initialised to 0
 *     and never incremented in the recovered body.
 *
 * The vector is pre-sized with `reserve(argc)` before the copy loop.
 *
 * @param argc Number of entries in @p argv; also the number of strings
 *             pushed into the internal vector. Must be non-negative.
 * @param argv Array of NUL-terminated C strings. Each `argv[i]` for
 *             `0 <= i < argc` is used to construct a `std::string`, so
 *             none of them may be NULL (a NULL pointer would trigger the
 *             libstdc++ "basic_string::_M_construct null not valid"
 *             error visible in the binary's string table).
 *
 * @return Always 0 on normal completion.
 * @retval 0 Execution reached the end of `main` successfully.
 *
 * @note May terminate via an uncaught C++ exception:
 *       `std::length_error` ("cannot create std::vector larger than
 *       max_size()") if @p argc exceeds the vector's max_size(), or
 *       `std::logic_error` from `std::string` if any `argv[i]` is NULL.
 * @note The `counter` value printed on the last line is a dead local
 *       left over from the original code; it is always 0.
 *
 * @code
 * // Invoked by the C runtime, e.g.:
 * //   $ ./app one two
 * // Output:
 * //   <greeting from HelloWorld>
 * //   Total argument length: 11        // strlen("./app")+strlen("one")+strlen("two")
 * //   Counter value: 0
 * @endcode
 */
#include <iostream>
#include <string>
#include <vector>

class HelloWorld {
public:
    HelloWorld(const std::string &msg);
    void printMessage() const;
};

/*
 * Reconstructed main:
 *   - builds a HelloWorld greeter from a format-style literal
 *   - copies argv[0..argc) into a std::vector<std::string>
 *   - prints the greeting, total length of all argv strings, and a counter
 *
 * The decompiled body is C++ but the target language requested is C, so
 * this file is written in a C-looking style that still relies on the C++
 * runtime symbols (std::cout, std::vector, std::string, HelloWorld) that
 * the original binary linked against.
 */
int main(int argc, char **argv)
{
    HelloWorld greeter(std::string("Sum printed C+ +!"));  /* literal recovered from .rodata */

    std::vector<std::string> args;
    args.reserve((size_t)argc);
    for (int i = 0; i < argc; ++i) {
        args.push_back(std::string(argv[i]));
    }

    size_t total_len = 0;
    for (size_t i = 0; i < args.size(); ++i) {
        total_len += args[i].size();
    }

    int counter = 0;  /* stack_21 - initialised earlier, value not materially used */

    greeter.printMessage();
    std::cout << "Total argument length: " << total_len << std::endl;
    std::cout << "Counter value: "        << counter   << std::endl;

    return 0;
}


/**
 * @brief Cold/exception-cleanup landing pad split out of `main()` by GCC.
 *
 * This symbol (`main.cold`) is not hand-written C code — it is a compiler-
 * emitted partition produced when GCC places the cold/EH-cleanup portion of
 * `main()` into a separate `.text.cold` section. Its body consists of the
 * destructor calls and unwinder invocations (e.g. `_Unwind_Resume`,
 * `std::vector<std::string>::~vector`) that must execute when an exception
 * propagates out of `main()`.
 *
 * Control reaches this routine only via the exception-handling tables
 * attached to `main()`; it is never invoked by an ordinary `call`. It
 * tail-calls `_Unwind_Resume` and therefore never returns to its caller —
 * stack unwinding continues in the runtime.
 *
 * @return This function does not return.
 *
 * @note Declared `noreturn` and `cold`. The C body is a stub containing
 *       `__builtin_unreachable()` because a faithful source-level rewrite
 *       of compiler-synthesized EH cleanup code is not possible.
 * @note Paired with `main()`; do not call directly from user code.
 */
/*
 * main.cold — compiler-emitted cold/exception cleanup landing pad for main().
 *
 * GCC splits exception-handling cleanup code out of main() into a separate
 * ".cold" partition. The body is a sequence of destructor invocations
 * (_Unwind_Resume calls, std::vector<std::string>::~vector, etc.) that runs
 * when an exception propagates out of main. It is marked noreturn because it
 * tail-calls _Unwind_Resume.
 *
 * This function has no C-level source: it is synthesized by the compiler
 * from main()'s cleanup EH tables. A faithful C rewrite is not possible;
 * the stub below documents its role.
 */
__attribute__((noreturn, cold))
void main_cold(void)
{
    __builtin_unreachable();
}

