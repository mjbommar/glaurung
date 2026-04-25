// src/hello.cpp
// Recovered from hello-gcc-O2 by glaurung source-recovery

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>
#include "types.h"
#include "strings.h"

/**
 * @brief Program entry point: prints two greetings, then totals argv lengths.
 *
 * Constructs a (currently unrecoverable) 22-byte greeting std::string and
 * invokes HelloWorld::printMessage() on a first instance. It then copies the
 * argv array into a std::vector<std::string> (reserving @p argc slots up
 * front), summing the lengths of every argument. After building an
 * 11-character "Sum printer" label, it invokes HelloWorld::printMessage() on
 * a second instance and writes two lines to std::cout:
 *   - "Total argument length: " followed by the accumulated length.
 *   - "Counter value: " followed by a counter whose source could not be
 *     recovered from the decompilation (emitted as 0 here).
 *
 * @param argc Number of entries in @p argv; used both as the loop bound and
 *             as the initial capacity reserved in the argument vector.
 * @param argv Array of NUL-terminated argument strings. Each entry is copied
 *             into a std::string; a NULL entry triggers the
 *             "basic_string::_M_construct null not valid" logic_error path.
 *
 * @return Always 0 on normal completion.
 * @retval 0 Success.
 *
 * @note May throw std::logic_error ("basic_string::_M_construct null not
 *       valid") if any argv[i] is NULL, and std::length_error ("cannot
 *       create std::vector larger than max_size()") if @p argc exceeds
 *       std::vector<std::string>::max_size().
 * @note The first greeting string and the "Counter value:" counter source
 *       were not fully recoverable from the binary; the reconstruction is
 *       approximate.
 *
 * @code
 * // Typical invocation from the OS loader:
 * //   $ ./prog one two three
 * // Output (schematically):
 * //   <greeting>
 * //   <greeting>
 * //   Total argument length: 17
 * //   Counter value: 0
 * @endcode
 */
// NOTE: prototype is C, but the binary is a C++ program using std::vector,
// std::string, std::cout, and a HelloWorld class. Surface syntax below is C++.
#include <iostream>
#include <string>
#include <vector>


int main(int argc, char **argv)
{
    // First greeting object: a std::string built from a 22-byte (0x16) blob
    // formed by concatenating an 8-byte word loaded from rodata (offset 0x20a0,
    // unrecoverable without the data section) with the literal "m C+f" via
    // immediates 0x2b43206d ("m C+f") and 0x212b ("+!"). Exact text unknown.
    std::string greeting;
    {
        char tmp[24];
        // bytes 0..7   : *(uint64_t*)&rodata[0x20a0]   (unknown)
        // bytes 8..11  : 0x2b43206d  -> "m C+f"
        // bytes 12..15 : 0x0000212b  -> "+!\0\0"
        // length = 0x16
        // (Reconstruction approximate; rodata bytes not recoverable.)
        std::memcpy(tmp, /*rodata[0x20a0]*/ "", 8);
        *reinterpret_cast<uint32_t*>(tmp + 8)  = 0x2b43206du;
        *reinterpret_cast<uint32_t*>(tmp + 12) = 0x0000212bu;
        tmp[0x16] = '\0';
        greeting.assign(tmp, 0x16);
    }

    HelloWorld hello1;
    hello1.printMessage();

    // Copy argv[0..argc-1] into a vector<string>.
    std::vector<std::string> args;
    args.reserve(static_cast<std::size_t>(argc));
    for (int i = 0; i < argc; ++i) {
        if (argv[i] == nullptr) {
            // basic_string::_M_construct null not valid
            throw std::logic_error(ERR_STRING_NULL_NOT_VALID);
        }
        args.emplace_back(argv[i]);
    }

    // Sum the lengths of all collected argument strings.
    std::size_t total_length = 0;
    for (const std::string &s : args) {
        total_length += s.size();
    }

    // Second greeting object: 11-byte literal "Sum printer".
    //   0x6e697270206d7553 = "Sum prin"
    //   0x6574             = "te"
    //   trailing 'r'
    std::string sum_label("Sum printer", 11);

    HelloWorld hello2;
    hello2.printMessage();

    std::cout << LBL_TOTAL_ARG_LENGTH << total_length << std::endl;

    // Counter value source could not be traced in the decompilation.
    int counter_value = 0;
    std::cout << COUNTER_VALUE_LABEL << counter_value << std::endl;

    return 0;
}


/**
 * @brief Prints the object's stored message to std::cout and bumps the call counter.
 *
 * Writes `this->message` (a std::string at offset 0x00) to standard output
 * followed by `std::endl` (newline + flush), then increments `this->call_count`
 * (a `long` at offset 0x20). The compiled body is the canonical g++ -O2
 * lowering of `std::cout << message << std::endl;` — it calls
 * `std::__ostream_insert` for the string insertion and inlines the `endl`
 * sequence (locate `std::cout`'s ctype<char> facet via the ios_base table at
 * +0xF0, test the facet's `do_widen` vtable slot at +0x38, then either widen
 * '\n' + `sputc` + `flush` or take the fast path).
 *
 * @param this Pointer to the HelloWorld instance whose `message` is printed
 *             and whose `call_count` is incremented. Must be non-null and
 *             fully constructed (the embedded std::string is dereferenced).
 *
 * @return No value is returned.
 *
 * @note Has the side effects of writing to `std::cout` (which may flush) and
 *       mutating `this->call_count`. Not thread-safe with respect to either
 *       `std::cout` or the counter.
 *
 * @code
 *     HelloWorld hw;            // message initialized elsewhere
 *     HelloWorld_printMessage(&hw);
 * @endcode
 */
/*
 * HelloWorld::printMessage()  (mangled: _ZN10HelloWorld12printMessageEv)
 *
 * The binary is C++; this file uses the `c` language tag only because the
 * caller requested it.  The body below is what the C++ source almost
 * certainly looked like before compilation.
 *
 *     class HelloWorld {
 *         std::string message;   // offset 0x00, sizeof == 0x20 in libstdc++
 *         long        call_count; // offset 0x20
 *     };
 *
 *     void HelloWorld::printMessage() {
 *         std::cout << self->message << std::endl;
 *         ++self->call_count;
 *     }
 *
 * The lowered code at offset 0x1280 is std::__ostream_insert (operator<<
 * for std::string), and the vtable / locale-ctype dance that follows
 * (load cout's vtable, fetch the virtual-base offset at [vt-0x18], index
 * into the ios_base at +0xF0 to get the ctype<char> facet, test the
 * facet's vtable slot at +0x38, then either widen('\n') + sputc + flush
 * or take the fast path) is the canonical inlined expansion of
 * std::endl emitted by g++ at -O2.
 */

void HelloWorld_printMessage(HelloWorld *self)
{
    std::cout << self->message << std::endl;
    ++self->call_count;
}


/**
 * @brief Cold/exception-cleanup partition of `main()` (compiler-generated).
 *
 * GCC's hot/cold function splitting emits the rarely-taken paths of `main`
 * into a separate `main.cold` symbol. In this binary the cold partition holds
 * the C++ exception landing pad for `main`: when an exception propagates out
 * of the try-region, control transfers here to destroy the local
 * `std::vector<std::string>` and then resume stack unwinding.
 *
 * Concretely, the body performs two actions:
 *   1. Invokes the base-object destructor of `std::vector<std::string>`
 *      (`_ZNSt6vector...D2Ev`) on the vector that lived in `main`'s frame.
 *   2. Tail-calls `_Unwind_Resume`, handing the in-flight exception object
 *      back to the libgcc/libunwind runtime so unwinding can continue past
 *      `main`.
 *
 * Because `_Unwind_Resume` never returns, this function never returns either;
 * it is marked `noreturn` and `cold`. It is not user code and is never called
 * directly — the personality routine dispatches to it via the `.gcc_except_table`
 * entry attached to `main`.
 *
 * @note The "parameters" shown in the decompiled pseudocode (`strings`,
 *       `exc_obj`) are not real arguments; the function takes no arguments
 *       and recovers the vector address and the in-flight exception object
 *       from `main`'s stack frame / the unwind context set up by the
 *       personality routine.
 * @note Despite appearing in the symbol table, this routine is unreachable
 *       on the normal-return path of `main`.
 *
 * @return This function does not return.
 */
/*
 * main.cold — compiler-generated cold/exception-cleanup partition of main().
 *
 * GCC splits cold paths (typically the landing pads that run destructors when
 * an exception unwinds through main) into a separate `.cold` symbol.  The body
 * is therefore not ".rela.plt" user code — it is just the unwind cleanup for a
 * `std::vector<std::string>` local in main().  It ends by re-raising the
 * in-flight exception (or calling _Unwind_Resume), which is why the symbol is
 * marked `noreturn`.
 *
 * There is no meaningful C-level rewrite: the pseudocode shows a destructor
 * call on the vector followed by a tail call into the unwind runtime.  We
 * reproduce that shape with an `extern "C"`-style stub.
 */

extern void _ZNSt6vectorINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEESaIS5_EED2Ev(void *self);
extern void _Unwind_Resume(void *exc) __attribute__((noreturn));

void main_cold(void) __attribute__((noreturn, cold));

void main_cold(void)
{
    /*
     * Cleanup landing pad for main(): destroy the local
     * std::vector<std::string> and resume unwinding.
     */
    void *strings   = __builtin_frame_address(0);  /* placeholder for &local vector */
    void *exc_obj   = __builtin_frame_address(0);  /* placeholder for in-flight exception */

    _ZNSt6vectorINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEESaIS5_EED2Ev(strings);
    _Unwind_Resume(exc_obj);
}

