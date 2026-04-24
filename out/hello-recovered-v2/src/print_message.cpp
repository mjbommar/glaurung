// src/print_message.cpp
// Recovered from hello-gcc-O2 by glaurung source-recovery

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

/**
 * @brief Writes the object's stored message to std::cout, followed by a newline
 *        flush, and increments the invocation counter.
 *
 * Emits exactly @c this->length bytes from @c this->message via
 * @c std::cout.write, then inserts @c std::endl (which outputs '\n' and
 * flushes the stream). After the write, @c this->call_count is incremented
 * by one to track how many times this method has been invoked on the
 * instance.
 *
 * @note The compiler inlined the string insertion as a direct
 *       @c std::cout.write(message, length) call, and @c std::endl was
 *       expanded to the fast path that consults
 *       @c std::ctype<char>::_M_table[0x38] before either putting '\n'
 *       directly or falling back to the virtual @c do_widen path.
 * @note No bounds checking is performed; the caller must ensure
 *       @c message points to at least @c length valid bytes.
 * @note This member mutates @c call_count, so it is not @c const.
 */
// Note: the binary symbol is the C++ mangled name
// _ZN10HelloWorld12printMessageEv, so this is really C++.
// Rendered here in C++ per the original source intent; the requested
// target language "c" cannot faithfully express cout/endl.

struct HelloWorld {
    const char *message;   // +0x00
    std::size_t length;    // +0x08
    // ... padding / unrecovered members ...
    int         call_count;// +0x20
};

void HelloWorld::printMessage()
{
    // std::cout << message << std::endl;
    //
    // The compiler inlined operator<<(ostream&, <string-like>) as a
    // direct cout.write(message, length) followed by the std::endl
    // fast path (check ctype<char>::_M_table[0x38] flags; if set, put
    // '\n' directly, otherwise call ctype::do_widen virtually and
    // then put). That whole sequence is just `<< std::endl`.
    std::cout.write(this->message,
                    static_cast<std::streamsize>(this->length));
    std::cout << std::endl;

    ++this->call_count;
}

