// src/main.cpp
// Recovered from hello-gcc-O2 by glaurung source-recovery

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

/**
 * @brief Cold/exception cleanup landing pad split out of main().
 *
 * This is the GCC-emitted `.cold` partition for `main()`. It is the
 * landing pad reached when an exception propagates out of `main()` while
 * the local `std::vector<std::string>` (referenced here as the external
 * symbol `strings`) is still live. It performs the required automatic
 * cleanup and then forwards the in-flight exception back to the unwinder.
 *
 * Specifically, it:
 *   - Invokes the base-object destructor
 *     `std::vector<std::string, std::allocator<std::string>>::~vector()`
 *     on the address of `strings`, releasing the vector's heap storage
 *     and destroying each contained `std::string`.
 *   - Calls `__cxa_rethrow()` to continue propagating the current
 *     exception up the stack.
 *
 * @return This function does not return. It is marked `noreturn` because
 *         `__cxa_rethrow()` never returns normally; control either
 *         transfers to an outer handler or the runtime calls
 *         `std::terminate()`.
 *
 * @note The function is marked `cold` — it is only entered on the
 *       exceptional path out of `main()` and is never invoked directly
 *       from ordinary control flow.
 * @note The `strings` symbol is the same `std::vector<std::string>`
 *       automatic that lives in `main()`'s frame; this cleanup pad reaches
 *       it via the unwinder-restored frame, not via a parameter.
 * @note Reconstructed from disassembly: only the destructor call and the
 *       rethrow are recovered; the surrounding frame setup and
 *       `_Unwind_Resume`/personality plumbing emitted by the compiler are
 *       elided.
 */
/*
 * main.cold — compiler-emitted cold/exception cleanup landing pad for main().
 *
 * The "cold" partition produced by GCC for functions that contain C++
 * exception edges normally just runs the local destructors and re-raises
 * (or aborts).  In this binary the only non-trivial automatic with a
 * destructor in main() is a std::vector<std::string>, so the cold half
 * simply invokes ~vector<string>() on it.
 *
 * The body is unwinder boilerplate (frame setup / _Unwind_Resume), so it
 * is reconstructed here only at the level of the destructor call that the
 * disassembly actually shows.  The function never returns to its caller.
 */
extern void __cxa_rethrow(void) __attribute__((noreturn));
extern void _ZNSt6vectorINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEESaIS5_EED2Ev(void *);

__attribute__((noreturn, cold))
void main_cold(void)
{
    extern void *strings;   /* the std::vector<std::string> local from main() */

    /* Run the destructor for the vector of strings that was live when the
       exception was thrown, then resume unwinding. */
    _ZNSt6vectorINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEESaIS5_EED2Ev(&strings);

    __cxa_rethrow();
}

